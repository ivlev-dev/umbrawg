/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _UWG_QUEUEING_H
#define _UWG_QUEUEING_H

#include "peer.h"
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ip_tunnels.h>

struct uwg_device;
struct uwg_peer;
struct multicore_worker;
struct crypt_queue;
struct prev_queue;
struct sk_buff;

/* queueing.c APIs: */
int uwg_packet_queue_init(struct crypt_queue *queue, work_func_t function,
			 unsigned int len);
void uwg_packet_queue_free(struct crypt_queue *queue, bool purge);
int uwg_packet_queue_init_percpu(struct crypt_queue *queue, work_func_t function,
				unsigned int len);
void uwg_packet_queue_free_percpu(struct crypt_queue *queue, bool purge);
struct multicore_worker __percpu *
uwg_packet_percpu_multicore_worker_alloc(work_func_t function, void *ptr);

/* receive.c APIs: */
void uwg_packet_receive(struct uwg_device *uwg, struct sk_buff *skb);
void uwg_packet_handshake_receive_worker(struct work_struct *work);
void uwg_packet_deliver_inner(struct uwg_peer *peer, struct sk_buff *skb,
			      u8 ds, bool use_napi);
/* NAPI poll function: */
int uwg_packet_rx_poll(struct napi_struct *napi, int budget);
/* Workqueue worker: */
void uwg_packet_decrypt_worker(struct work_struct *work);

/* send.c APIs: */
void uwg_packet_send_queued_handshake_initiation(struct uwg_peer *peer,
						bool is_retry);
void uwg_packet_send_handshake_response(struct uwg_peer *peer);
void uwg_packet_send_handshake_cookie(struct uwg_device *uwg,
				     struct sk_buff *initiating_skb,
				     __le32 sender_index);
void uwg_packet_send_keepalive(struct uwg_peer *peer);
int uwg_packet_send_control(struct uwg_peer *peer, const u8 *frame, size_t len);
void uwg_packet_send_fec_frames(struct uwg_peer *peer,
				struct sk_buff_head *frames);
void uwg_packet_purge_staged_packets(struct uwg_peer *peer);
void uwg_packet_send_staged_packets(struct uwg_peer *peer);
/* Workqueue workers: */
void uwg_packet_handshake_send_worker(struct work_struct *work);
void uwg_packet_tx_worker(struct work_struct *work);
void uwg_packet_encrypt_worker(struct work_struct *work);

enum packet_state {
	PACKET_STATE_UNCRYPTED,
	PACKET_STATE_CRYPTED,
	PACKET_STATE_DEAD
};

struct packet_cb {
	u64 nonce;
	struct noise_keypair *keypair;
	atomic_t state;
	u32 mtu;
	u32 type;
	u32 padding;
	u32 pace_len;
	u8 ds;
	bool is_keepalive;
	bool is_fec;
	/* Parity count of the FEC block a shard belongs to; also the maximum
	 * number of shards that may share one GSO superdatagram. Zero for
	 * non-FEC traffic and for blocks encoded without parity.
	 */
	u8 fec_m;
};

#define PACKET_CB(skb) ((struct packet_cb *)((skb)->cb))
#define PACKET_PEER(skb) (PACKET_CB(skb)->keypair->entry.peer)

static inline bool uwg_check_packet_protocol(struct sk_buff *skb)
{
	__be16 real_protocol = ip_tunnel_parse_protocol(skb);
	return real_protocol && skb->protocol == real_protocol;
}

static inline void uwg_reset_packet(struct sk_buff *skb, bool encapsulating)
{
	u8 l4_hash = skb->l4_hash;
	u8 sw_hash = skb->sw_hash;
	u32 hash = skb->hash;
	skb_scrub_packet(skb, true);
	memset(&skb->headers, 0, sizeof(skb->headers));
	if (encapsulating) {
		skb->l4_hash = l4_hash;
		skb->sw_hash = sw_hash;
		skb->hash = hash;
	}
	skb->queue_mapping = 0;
	skb->nohdr = 0;
	skb->peeked = 0;
	skb->mac_len = 0;
	skb->dev = NULL;
#ifdef CONFIG_NET_SCHED
	skb->tc_index = 0;
#endif
	skb_reset_redirect(skb);
	skb->hdr_len = skb_headroom(skb);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb_probe_transport_header(skb);
	skb_reset_inner_headers(skb);
}

static inline int uwg_cpumask_choose_online(int *stored_cpu, unsigned int id)
{
	unsigned int cpu = *stored_cpu, cpu_index, i;

	if (unlikely(cpu >= nr_cpu_ids ||
		     !cpumask_test_cpu(cpu, cpu_online_mask))) {
		cpu_index = id % cpumask_weight(cpu_online_mask);
		cpu = cpumask_first(cpu_online_mask);
		for (i = 0; i < cpu_index; ++i)
			cpu = cpumask_next(cpu, cpu_online_mask);
		*stored_cpu = cpu;
	}
	return cpu;
}

/* This function is racy, in the sense that it's called while last_cpu is
 * unlocked, so it could return the same CPU twice. Adding locking or using
 * atomic sequence numbers is slower though, and the consequences of racing are
 * harmless, so live with it.
 */
static inline int uwg_cpumask_next_online(int *last_cpu)
{
	int cpu = cpumask_next(READ_ONCE(*last_cpu), cpu_online_mask);
	if (cpu >= nr_cpu_ids)
		cpu = cpumask_first(cpu_online_mask);
	WRITE_ONCE(*last_cpu, cpu);
	return cpu;
}

void uwg_prev_queue_init(struct prev_queue *queue);

/* Multi producer */
bool uwg_prev_queue_enqueue(struct prev_queue *queue, struct sk_buff *skb);

/* Single consumer */
struct sk_buff *uwg_prev_queue_dequeue(struct prev_queue *queue);

/* Single consumer */
static inline struct sk_buff *uwg_prev_queue_peek(struct prev_queue *queue)
{
	if (queue->peeked)
		return queue->peeked;
	queue->peeked = uwg_prev_queue_dequeue(queue);
	return queue->peeked;
}

/* Single consumer */
static inline void uwg_prev_queue_drop_peeked(struct prev_queue *queue)
{
	queue->peeked = NULL;
}

static inline bool uwg_queue_wakeup_arm(struct multicore_worker *worker, int cpu,
					struct workqueue_struct *wq)
{
	if (atomic_xchg(&worker->pending, 1))
		return false;
	queue_work_on(cpu, wq, &worker->work);
	return true;
}

static inline bool uwg_queue_wakeup_drained(struct multicore_worker *worker,
					    struct crypt_queue *queue)
{
	atomic_set(&worker->pending, 0);
	smp_mb();
	if (likely(__ptr_ring_empty(&queue->ring)))
		return true;
	atomic_set(&worker->pending, 1);
	return false;
}

/*
 * Work stealing: a per-CPU ring keeps a flow's chains together for
 * batching, but a single flow only ever feeds one CPU. When a peer's
 * chain backlog on that CPU grows past the threshold, the producer asks
 * another CPU to steal from it. Idle workers then drain the victim's
 * ring exactly like their own; the old round-robin design did the same
 * per chain, so ordering and the packet state machine are unaffected.
 *
 * The threshold counts queue entries, and the unit differs by direction:
 * on TX an entry is a chain of up to MAX_STAGED_PACKETS (128) skbs, so
 * four entries is up to ~512 skb of backlog; on RX an entry is a single
 * skb, so four entries are four skbs. RX has no chain batching and a
 * single high-pps flow fills its CPU ring with individual skbs, so the
 * same number intentionally triggers much earlier in byte terms there.
 * One number for both keeps the policy simple; a split TX/RX threshold
 * was measured (4/32/128 skb) and did not improve either direction, so the
 * shared value stays. A healthy multi-peer pipeline
 * keeps only a couple of entries queued per peer and stays on the
 * batching path; a single flow that outruns its CPU grows a real backlog
 * and asks for help early. Four entries measured the best balance:
 * single-flow ~3.1 Gbit/s (local-only ~2.4, legacy round-robin ~2.6)
 * while 50 peers stayed at ~8.4 Gbit/s with fairness < 2.1. A threshold
 * of 8 still helped but left single-flow at ~2.7.
 */
#define UWG_CRYPT_STEAL_THRESHOLD 4

/*
 * Claim the pending steal request. Only a worker other than the victim
 * may take it, and only one helper claims it (cmpxchg to -1). Returns the
 * victim's queue, or NULL when there is nothing to do.
 */
static inline struct crypt_queue *
uwg_crypt_steal_claim(struct crypt_queue *queue)
{
	struct crypt_queue *parent = READ_ONCE(queue->parent);
	struct crypt_queue *victim;
	int cpu;

	if (unlikely(!parent))
		return NULL;
	cpu = atomic_read(&parent->steal_cpu);
	if (unlikely(cpu < 0))
		return NULL;
	victim = per_cpu_ptr(parent->worker, cpu)->ptr;
	if (unlikely(!victim || victim == queue))
		return NULL;
	return atomic_cmpxchg(&parent->steal_cpu, cpu, -1) == cpu ?
		       victim : NULL;
}

/*
 * Drop a request we own. cmpxchg keeps a request published by somebody
 * else (or already claimed by a helper) intact.
 */
static inline void uwg_crypt_steal_cancel(struct crypt_queue *device_queue,
					  int own_cpu)
{
	atomic_cmpxchg(&device_queue->steal_cpu, own_cpu, -1);
}

/*
 * Called by the producer when a peer's backlog crosses the threshold.
 * steal_cpu doubles as the request slot: cmpxchg publishes at most one
 * request at a time and one helper is woken per request, rotated over
 * the online CPUs, so a burst cannot turn into a wakeup storm. Once a
 * helper has claimed the request, later overflows may publish another
 * one and several helpers can end up draining the same victim ring; that
 * is safe (ptr_ring consumer_lock) and bounded by nr_cpus. If a tighter
 * in-flight bound is ever needed, gate publishing on the number of
 * helpers already draining that ring.
 */
static inline void uwg_crypt_maybe_steal(struct crypt_queue *device_queue,
					 const struct prev_queue *peer_queue,
					 int own_cpu,
					 struct workqueue_struct *wq)
{
	struct multicore_worker *worker;
	int cpu;

	if (atomic_read(&peer_queue->count) <= UWG_CRYPT_STEAL_THRESHOLD)
		return;
	if (atomic_cmpxchg(&device_queue->steal_cpu, -1, own_cpu) != -1)
		return;

	cpu = uwg_cpumask_next_online(&device_queue->helper_cpu);
	if (unlikely(cpu == own_cpu))
		cpu = uwg_cpumask_next_online(&device_queue->helper_cpu);
	if (unlikely(cpu == own_cpu)) {
		/* Only one CPU online: nobody can help. */
		uwg_crypt_steal_cancel(device_queue, own_cpu);
		return;
	}
	worker = per_cpu_ptr(device_queue->worker, cpu);
	if (!uwg_queue_wakeup_arm(worker, cpu, wq))
		/* The helper was already queued and may have passed its
		 * claim point; retry on the next overflow instead of
		 * leaving the request stuck. If the target CPU goes
		 * offline before its work runs, the bound pool is
		 * disassociated and a worker runs the queued work on an
		 * online CPU, so the request is still claimed.
		 */
		uwg_crypt_steal_cancel(device_queue, own_cpu);
}

/*
 * Pick the next spill candidate from @mask for producer @own and advance
 * @cursor past it. Candidates are visited in CPU-id order with wraparound,
 * the producer's own CPU is never returned, and the walk gives up after two
 * steps so a mask that only contains @own cannot spin. This is the exact
 * 2-CPU case: with mask {0,1} and own 0 it returns 1 on the first step,
 * instead of consuming the loop iteration on the skipped own CPU.
 */
static inline int uwg_spill_next_cpu(const struct cpumask *mask, int own,
				     int *cursor)
{
	int target = READ_ONCE(*cursor);
	int i;

	for (i = 0; i < 2; ++i) {
		target = cpumask_next(target, mask);
		if (target >= nr_cpu_ids)
			target = cpumask_first(mask);
		if (target != own) {
			WRITE_ONCE(*cursor, target);
			return target;
		}
	}
	return -1;
}

/*
 * Put one skb on this CPU's ring, or spill it to another online CPU when the
 * local ring is momentarily full. The producer stays local and batched in the
 * common case; only an overflow pays for the walk below. At most
 * UWG_SPILL_CANDIDATES rings are tried, starting after the per-producer
 * sticky cursor, so an overflow cannot turn into an O(ncpus) scan or a
 * wakeup storm under saturation. The cursor is per producer CPU, which keeps
 * a hot producer/target pair together without a shared cache line.
 *
 * Ordering is unaffected: the peer queue holds the packets in arrival order
 * and its consumer waits for the head skb's state, so a packet processed by
 * a helper CPU cannot overtake an earlier one.
 *
 * The shared handshake queue does not use this path: it has a single ring and
 * no per-CPU worker, so uwg_queue_enqueue_per_device_and_peer() is only ever
 * called with the per-CPU encrypt/decrypt queues.
 */
#define UWG_SPILL_CANDIDATES 2

static inline int uwg_queue_produce_crypt(struct crypt_queue *device_queue,
					  struct multicore_worker *worker,
					  struct sk_buff *skb, int cpu,
					  struct workqueue_struct *wq)
{
	struct multicore_worker *target_worker;
	struct crypt_queue *queue;
	int *cursor, target, first = -1;
	int i;

	queue = worker->ptr;
	if (likely(!ptr_ring_produce_bh(&queue->ring, skb))) {
		uwg_queue_wakeup_arm(worker, cpu, wq);
		return 0;
	}

	if (num_online_cpus() < 2)
		return -EPIPE;

	cursor = per_cpu_ptr(device_queue->spill_cpu, cpu);
	for (i = 0; i < UWG_SPILL_CANDIDATES; ++i) {
		target = uwg_spill_next_cpu(cpu_online_mask, cpu, cursor);
		if (target < 0 || target == first)
			break;
		if (first < 0)
			first = target;

		target_worker = per_cpu_ptr(device_queue->worker, target);
		queue = target_worker->ptr;
		if (!ptr_ring_produce_bh(&queue->ring, skb)) {
			uwg_queue_wakeup_arm(target_worker, target, wq);
			atomic64_inc(&device_queue->spill_count);
			return 0;
		}
	}

	return -EPIPE;
}

static inline int uwg_queue_enqueue_per_device_and_peer(
	struct crypt_queue *device_queue, struct prev_queue *peer_queue,
	struct sk_buff *skb, struct workqueue_struct *wq)
{
	struct multicore_worker *worker;
	int cpu;

	atomic_set_release(&PACKET_CB(skb)->state, PACKET_STATE_UNCRYPTED);
	/* We first queue this up for the peer ingestion, but the consumer
	 * will wait for the state to change to CRYPTED or DEAD before.
	 */
	if (unlikely(!uwg_prev_queue_enqueue(peer_queue, skb)))
		return -ENOSPC;

	/* Then we queue it up in the device queue, which consumes the
	 * packet as soon as it can.
	 *
	 * The ring is the one of the CPU that produced the chain, not a
	 * round-robin pick. Spreading a single peer's traffic over every
	 * per-CPU ring leaves each ring holding one short chain, so a worker
	 * is woken for almost every chain, the batch stays tiny, and the skb
	 * is encrypted or decrypted on a CPU that will never touch it again.
	 * At 50 peers that tripled the context-switch rate, pushed the
	 * softirq backlog into ksoftirqd and left the CPUs idle between
	 * wakeups. A TCP flow is emitted from one CPU, so staying local lets
	 * a worker wake once and drain a real batch with warm cachelines.
	 * The only exception is uwg_queue_produce_crypt() below: when the
	 * local ring is full the skb spills to another CPU instead of being
	 * dropped, which is rare enough not to affect the batching above.
	 */
	cpu = get_cpu();
	worker = per_cpu_ptr(device_queue->worker, cpu);
	if (unlikely(uwg_queue_produce_crypt(device_queue, worker, skb, cpu,
					     wq))) {
		put_cpu();
		return -EPIPE;
	}
	/* The single flow that backs up its ring gets idle CPUs to help. */
	uwg_crypt_maybe_steal(device_queue, peer_queue, cpu, wq);
	put_cpu();
	return 0;
}

static inline void uwg_queue_enqueue_per_peer_tx(struct sk_buff *skb, enum packet_state state)
{
	/* We take a reference, because as soon as we call atomic_set, the
	 * peer can be freed from below us.
	 */
	struct uwg_peer *peer = uwg_peer_get(PACKET_PEER(skb));

	atomic_set_release(&PACKET_CB(skb)->state, state);
	queue_work_on(uwg_cpumask_choose_online(&peer->serial_work_cpu, peer->internal_id),
		      peer->device->packet_crypt_wq, &peer->transmit_packet_work);
	uwg_peer_put(peer);
}

static inline void uwg_queue_enqueue_per_peer_rx(struct sk_buff *skb, enum packet_state state)
{
	/* We take a reference, because as soon as we call atomic_set, the
	 * peer can be freed from below us.
	 */
	struct uwg_peer *peer = uwg_peer_get(PACKET_PEER(skb));

	atomic_set_release(&PACKET_CB(skb)->state, state);
	napi_schedule(&peer->napi);
	uwg_peer_put(peer);
}

#ifdef DEBUG
bool uwg_packet_counter_selftest(void);
bool uwg_queueing_selftest(void);
#endif

#endif /* _UWG_QUEUEING_H */
