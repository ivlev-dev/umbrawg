// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifdef DEBUG

#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/bitmap.h>

#define UWGT_PRODUCERS 4
#define UWGT_ITEMS_PER_PRODUCER 25000
#define UWGT_RING_LEN 256
#define UWGT_TIMEOUT HZ

#define UWGT_STEAL_ITEMS 256
#define UWGT_STEAL_RING_LEN (2 * UWGT_STEAL_ITEMS)
#define UWGT_STEAL_TIMEOUT HZ

struct uwg_queueing_selftest_ctx {
	struct crypt_queue queue;
	struct workqueue_struct *wq;
	atomic_t consumed;
	atomic_t produced;
	atomic_t aborted;
	bool token;
};

static void uwg_queueing_selftest_worker(struct work_struct *work)
{
	struct multicore_worker *worker = container_of(work,
						       struct multicore_worker,
						       work);
	struct crypt_queue *queue = worker->ptr;
	struct uwg_queueing_selftest_ctx *ctx =
		container_of(queue, struct uwg_queueing_selftest_ctx, queue);
	void *item;

	for (;;) {
		while ((item = ptr_ring_consume_bh(&queue->ring)) != NULL)
			atomic_inc(&ctx->consumed);
		if (uwg_queue_wakeup_drained(worker, queue))
			break;
	}
}

static int uwg_queueing_selftest_producer(void *data)
{
	struct uwg_queueing_selftest_ctx *ctx = data;
	unsigned long deadline = jiffies + UWGT_TIMEOUT;
	unsigned int cpu = cpumask_first(cpu_online_mask);
	int i;

	for (i = 0; i < UWGT_ITEMS_PER_PRODUCER; ++i) {
		while (unlikely(ptr_ring_produce_bh(&ctx->queue.ring,
						    &ctx->token))) {
			if (time_after(jiffies, deadline)) {
				atomic_set(&ctx->aborted, 1);
				goto park;
			}
			cpu_relax();
		}
		uwg_queue_wakeup_arm(per_cpu_ptr(ctx->queue.worker, cpu), cpu,
				     ctx->wq);
		atomic_inc(&ctx->produced);
		cpu = cpumask_next(cpu, cpu_online_mask);
		if (cpu >= nr_cpu_ids)
			cpu = cpumask_first(cpu_online_mask);
	}
park:
	while (!kthread_should_stop())
		usleep_range(1000, 2000);
	return 0;
}

static void uwg_queueing_selftest_drain(struct crypt_queue *queue)
{
	while (ptr_ring_consume_bh(&queue->ring))
		;
}

/*
 * Work-stealing protocol tests. The per-CPU queue is the real one, built by
 * uwg_packet_queue_init_percpu(), so parent/steal_cpu/helper_cpu and the
 * per-CPU worker pending flags are exercised as in production. The worker
 * only drops the pending flag: the protocol tests drive claim/cancel by
 * hand and the drain test consumes the ring from two kthreads.
 */
struct uwg_steal_selftest_ctx {
	struct crypt_queue *ring;
	DECLARE_BITMAP(seen, UWGT_STEAL_ITEMS);
	atomic_t consumed;
	atomic_t double_seen;
};

static void uwg_steal_selftest_worker(struct work_struct *work)
{
	struct multicore_worker *worker = container_of(work,
						       struct multicore_worker,
						       work);

	atomic_set(&worker->pending, 0);
}

static int uwg_steal_selftest_consumer(void *data)
{
	struct uwg_steal_selftest_ctx *ctx = data;

	while (!kthread_should_stop()) {
		void *item = ptr_ring_consume_bh(&ctx->ring->ring);
		unsigned long id;

		if (!item) {
			cpu_relax();
			cond_resched();
			continue;
		}
		id = (unsigned long)item - 1;
		if (unlikely(id >= UWGT_STEAL_ITEMS) ||
		    test_and_set_bit(id, ctx->seen))
			atomic_inc(&ctx->double_seen);
		atomic_inc(&ctx->consumed);
	}
	return 0;
}

static bool uwg_queueing_steal_selftest(int *test_num)
{
	struct uwg_steal_selftest_ctx *ctx;
	struct crypt_queue *own_q, *helper_q, *victim;
	struct crypt_queue dev;
	struct workqueue_struct *wq;
	struct task_struct *consumers[2];
	struct prev_queue peer;
	unsigned long deadline;
	unsigned int i;
	bool success = true;
	int own, helper, cpu, ret;

	if (num_online_cpus() < 2) {
		/* With one CPU the rotation always lands on own_cpu and the
		 * producer cancels the request; there is nothing to steal.
		 */
		pr_info("queueing self-test: steal protocol skipped on a single CPU\n");
		return true;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return false;

	ret = uwg_packet_queue_init_percpu(&dev, uwg_steal_selftest_worker,
					   UWGT_STEAL_RING_LEN);
	if (ret) {
		kfree(ctx);
		return false;
	}

	wq = alloc_workqueue("uwg-steal-selftest",
			     WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_PERCPU, 0);
	if (!wq) {
		uwg_packet_queue_free_percpu(&dev, false);
		kfree(ctx);
		return false;
	}

	own = cpumask_first(cpu_online_mask);
	helper = cpumask_next(own, cpu_online_mask);
	if (helper >= nr_cpu_ids)
		helper = cpumask_first(cpu_online_mask);
	own_q = per_cpu_ptr(dev.worker, own)->ptr;
	helper_q = per_cpu_ptr(dev.worker, helper)->ptr;
	atomic_set(&peer.count, 0);

	/* The victim's own worker must not consume its own request. */
	++*test_num;
	atomic_set(&dev.steal_cpu, own);
	if (uwg_crypt_steal_claim(own_q) ||
	    atomic_read(&dev.steal_cpu) != own) {
		pr_err("queueing self-test %d: FAIL (victim claim)\n", *test_num);
		success = false;
	}
	atomic_set(&dev.steal_cpu, -1);

	/* Exactly one helper may claim a request. */
	++*test_num;
	atomic_set(&dev.steal_cpu, own);
	victim = uwg_crypt_steal_claim(helper_q);
	if (victim != own_q ||
	    atomic_read(&dev.steal_cpu) != -1 ||
	    uwg_crypt_steal_claim(helper_q)) {
		pr_err("queueing self-test %d: FAIL (claim once)\n", *test_num);
		success = false;
	}

	/* Cancel only drops a request we published. The single-CPU
	 * branch uses the same helper, so this covers both call sites.
	 */
	++*test_num;
	atomic_set(&dev.steal_cpu, own);
	uwg_crypt_steal_cancel(&dev, own);
	if (atomic_read(&dev.steal_cpu) != -1) {
		pr_err("queueing self-test %d: FAIL (cancel own)\n", *test_num);
		success = false;
	}
	atomic_set(&dev.steal_cpu, helper);
	uwg_crypt_steal_cancel(&dev, own);
	if (atomic_read(&dev.steal_cpu) != helper) {
		pr_err("queueing self-test %d: FAIL (cancel foreign)\n", *test_num);
		success = false;
	}
	atomic_set(&dev.steal_cpu, -1);

	/* An overflow publishes the request and a helper claims it. */
	++*test_num;
	atomic_set(&peer.count, UWG_CRYPT_STEAL_THRESHOLD + 1);
	dev.helper_cpu = own;
	uwg_crypt_maybe_steal(&dev, &peer, own, wq);
	victim = uwg_crypt_steal_claim(helper_q);
	if (atomic_read(&dev.steal_cpu) != -1 || victim != own_q) {
		pr_err("queueing self-test %d: FAIL (publish/claim)\n", *test_num);
		success = false;
	}

	/* A helper that is already queued cannot be armed again, so the
	 * producer has to cancel its request instead of leaving it stuck.
	 */
	++*test_num;
	flush_workqueue(wq);
	atomic_set(&per_cpu_ptr(dev.worker, helper)->pending, 0);
	dev.helper_cpu = own;
	atomic_set(&per_cpu_ptr(dev.worker, helper)->pending, 1);
	atomic_set(&dev.steal_cpu, -1);
	uwg_crypt_maybe_steal(&dev, &peer, own, wq);
	if (atomic_read(&dev.steal_cpu) != -1) {
		pr_err("queueing self-test %d: FAIL (failed arm)\n", *test_num);
		success = false;
	}
	atomic_set(&per_cpu_ptr(dev.worker, helper)->pending, 0);
	atomic_set(&peer.count, 0);

	/* Two consumers drain one ring without losing or duplicating an
	 * item. This is the helper/owner pair on the same victim ring.
	 */
	++*test_num;
	ctx->ring = own_q;
	memset(ctx->seen, 0, sizeof(ctx->seen));
	atomic_set(&ctx->consumed, 0);
	atomic_set(&ctx->double_seen, 0);
	for (i = 0; i < UWGT_STEAL_ITEMS; ++i) {
		if (ptr_ring_produce_bh(&own_q->ring,
					(void *)(unsigned long)(i + 1))) {
			pr_err("queueing self-test %d: FAIL (produce)\n",
			       *test_num);
			success = false;
			break;
		}
	}

	consumers[0] = kthread_run(uwg_steal_selftest_consumer, ctx,
				   "uwg-steal-c0");
	consumers[1] = kthread_run(uwg_steal_selftest_consumer, ctx,
				   "uwg-steal-c1");
	if (IS_ERR(consumers[0]) || IS_ERR(consumers[1])) {
		pr_err("queueing self-test %d: FAIL (consumer)\n", *test_num);
		success = false;
	}

	deadline = jiffies + UWGT_STEAL_TIMEOUT;
	while (atomic_read(&ctx->consumed) != UWGT_STEAL_ITEMS &&
	       time_before(jiffies, deadline))
		usleep_range(1000, 2000);

	for (i = 0; i < ARRAY_SIZE(consumers); ++i)
		if (!IS_ERR(consumers[i]))
			kthread_stop(consumers[i]);

	if (atomic_read(&ctx->consumed) != UWGT_STEAL_ITEMS ||
	    atomic_read(&ctx->double_seen) ||
	    !__ptr_ring_empty(&own_q->ring)) {
		pr_err("queueing self-test %d: FAIL (dual drain)\n", *test_num);
		success = false;
	}

	destroy_workqueue(wq);
	/* The rings hold tokens, not skbs: drain them before freeing. */
	for_each_possible_cpu(cpu) {
		struct crypt_queue *q = per_cpu_ptr(dev.worker, cpu)->ptr;

		if (q)
			uwg_queueing_selftest_drain(q);
	}
	uwg_packet_queue_free_percpu(&dev, false);
	kfree(ctx);
	return success;
}

bool __init uwg_queueing_selftest(void)
{
	struct uwg_queueing_selftest_ctx *ctx;
	struct task_struct *threads[UWGT_PRODUCERS];
	unsigned int i, expected = UWGT_PRODUCERS * UWGT_ITEMS_PER_PRODUCER;
	unsigned long deadline;
	bool success = true;
	int ret, test_num = 0;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return false;

	atomic_set(&ctx->consumed, 0);
	atomic_set(&ctx->produced, 0);
	atomic_set(&ctx->aborted, 0);

	ret = uwg_packet_queue_init(&ctx->queue, uwg_queueing_selftest_worker,
				    UWGT_RING_LEN);
	if (ret)
		goto err_free;

	ctx->wq = alloc_workqueue("uwg-selftest",
				  WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_PERCPU,
				  0);
	if (!ctx->wq) {
		success = false;
		goto err_queue;
	}

	/*  1 */
	++test_num;
	if (!uwg_queue_wakeup_arm(
		    per_cpu_ptr(ctx->queue.worker, cpumask_first(cpu_online_mask)),
		    cpumask_first(cpu_online_mask), ctx->wq)) {
		pr_err("queueing self-test %d: FAIL\n", test_num);
		success = false;
	}

	/*  2 */
	++test_num;
	if (uwg_queue_wakeup_arm(
		    per_cpu_ptr(ctx->queue.worker, cpumask_first(cpu_online_mask)),
		    cpumask_first(cpu_online_mask), ctx->wq)) {
		pr_err("queueing self-test %d: FAIL\n", test_num);
		success = false;
	}

	flush_workqueue(ctx->wq);

	/*  3 */
	++test_num;
	if (uwg_queue_wakeup_arm(
		    per_cpu_ptr(ctx->queue.worker, cpumask_first(cpu_online_mask)),
		    cpumask_first(cpu_online_mask), ctx->wq)) {
		flush_workqueue(ctx->wq);
	} else {
		pr_err("queueing self-test %d: FAIL\n", test_num);
		success = false;
	}

	for (i = 0; i < UWGT_PRODUCERS; ++i) {
		threads[i] = kthread_run(uwg_queueing_selftest_producer, ctx,
					 "uwg-selftest-producer");
		if (IS_ERR(threads[i])) {
			threads[i] = NULL;
			success = false;
		}
	}

	deadline = jiffies + UWGT_TIMEOUT;
	while (atomic_read(&ctx->produced) != expected &&
	       !atomic_read(&ctx->aborted)) {
		if (time_after(jiffies, deadline))
			break;
		usleep_range(1000, 2000);
	}

	for (i = 0; i < UWGT_PRODUCERS; ++i) {
		if (!threads[i])
			continue;
		kthread_stop(threads[i]);
	}

	deadline = jiffies + UWGT_TIMEOUT;
	while (atomic_read(&ctx->consumed) != expected) {
		if (time_after(jiffies, deadline))
			break;
		usleep_range(1000, 2000);
	}
	flush_workqueue(ctx->wq);

	/*  5 */
	++test_num;
	if (atomic_read(&ctx->consumed) != expected ||
	    atomic_read(&ctx->produced) != expected ||
	    atomic_read(&ctx->aborted)) {
		pr_err("queueing self-test %d: FAIL\n", test_num);
		success = false;
	}

	/*  6 */
	++test_num;
	if (!__ptr_ring_empty(&ctx->queue.ring)) {
		pr_err("queueing self-test %d: FAIL\n", test_num);
		success = false;
	}

	if (!uwg_queueing_steal_selftest(&test_num))
		success = false;

	if (success)
		pr_info("queueing self-test: 1..%d passed\n", test_num);

	uwg_queueing_selftest_drain(&ctx->queue);
	destroy_workqueue(ctx->wq);
err_queue:
	uwg_packet_queue_free(&ctx->queue, false);
err_free:
	kfree(ctx);
	return success;
}

#endif
