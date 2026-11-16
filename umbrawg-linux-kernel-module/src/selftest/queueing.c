// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifdef DEBUG

#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/jiffies.h>

#define UWGT_PRODUCERS 4
#define UWGT_ITEMS_PER_PRODUCER 25000
#define UWGT_RING_LEN 256
#define UWGT_TIMEOUT HZ

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

	uwg_queueing_selftest_drain(&ctx->queue);
	destroy_workqueue(ctx->wq);
err_queue:
	uwg_packet_queue_free(&ctx->queue, false);
err_free:
	kfree(ctx);
	return success;
}

#endif
