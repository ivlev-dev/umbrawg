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

static inline int uwg_queue_enqueue_per_device_and_peer(
	struct crypt_queue *device_queue, struct prev_queue *peer_queue,
	struct sk_buff *skb, struct workqueue_struct *wq)
{
	struct multicore_worker *worker;
	struct crypt_queue *queue;
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
	 */
	cpu = get_cpu();
	worker = per_cpu_ptr(device_queue->worker, cpu);
	queue = worker->ptr;
	if (unlikely(ptr_ring_produce_bh(&queue->ring, skb))) {
		put_cpu();
		return -EPIPE;
	}
	uwg_queue_wakeup_arm(worker, cpu, wq);
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
