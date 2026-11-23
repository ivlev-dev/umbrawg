/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _UWG_DEVICE_H
#define _UWG_DEVICE_H

#include "junk.h"
#include "noise.h"
#include "allowedips.h"
#include "peerlookup.h"
#include "cookie.h"
#include "header_protection.h"
#include "type.h"

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/ptr_ring.h>
#include <linux/ratelimit.h>

struct uwg_device;

struct multicore_worker {
	void *ptr;
	struct work_struct work;
	atomic_t pending;
};

struct crypt_queue {
	/* Holds skb chains (up to MAX_STAGED_PACKETS each), not single skbs. */
	struct ptr_ring ring;
	struct multicore_worker __percpu *worker;
	/* Back-pointer from a per-CPU ring to the device-level queue; NULL
	 * for the shared handshake queue.
	 */
	struct crypt_queue *parent;
	/* Device-level: CPU whose ring is backed up, or -1. Idle workers
	 * steal from that ring until it drains.
	 */
	atomic_t steal_cpu;
	/* Device-level: round-robin cursor for picking the next helper. */
	int helper_cpu;
	/* Device-level: per-producer-CPU sticky cursor for the overflow
	 * spill path. NULL for the shared handshake queue, which has no
	 * per-CPU rings and never takes that path.
	 */
	int __percpu *spill_cpu;
	/* Device-level: successful ring overflows (informational). */
	atomic64_t spill_count;
	/* Round-robin cursor for the shared handshake queue only. The
	 * per-CPU crypt queues must not use it: their ring is chosen by the
	 * producing CPU (uwg_queue_enqueue_per_device_and_peer()), and
	 * spreading a flow over rings destroys worker batching.
	 */
	int last_cpu;
};

struct prev_queue {
	struct sk_buff *head, *tail, *peeked;
	struct { struct sk_buff *next, *prev; } empty; // Match first 2 members of struct sk_buff.
	atomic_t count;
};

struct uwg_device {
	struct net_device *dev;
	struct crypt_queue encrypt_queue, decrypt_queue, handshake_queue;
	struct sock __rcu *sock4, *sock6;
#define UWG_EXTRA_PORTS_MAX 8
#define UWG_EXTRA_PORTS_DEFAULT 0
#define UWG_FEC_MODE_OFF 0
#define UWG_FEC_MODE_ADAPTIVE 1
#define UWG_FEC_MAX_SHARDS 255
	struct sock __rcu *sock4_extra[UWG_EXTRA_PORTS_MAX];
	struct sock __rcu *sock6_extra[UWG_EXTRA_PORTS_MAX];
	u8 sock4_extra_count, sock6_extra_count;
	u8 extra_ports;
	u32 fec_mode;
	/* MTU of the path between peers, as configured by the user. The FEC
	 * MTU policy needs it to decide how large one shard datagram may be.
	 */
	u16 underlay_mtu;
	/* MTU the user asked for (`ip link set mtu` or the netdev default),
	 * and the one the FEC policy last programmed. They differ while FEC
	 * is enabled; a dev->mtu different from fec_applied_mtu means the
	 * operator changed it behind our back, and it is adopted as the new
	 * base by uwg_fec_refresh_mtu().
	 */
	u32 fec_base_mtu, fec_applied_mtu;
	atomic_t sock4_rr, sock6_rr;
	struct net __rcu *creating_net;
	struct noise_static_identity static_identity;
	struct workqueue_struct *packet_crypt_wq,*handshake_receive_wq, *handshake_send_wq;
	struct cookie_checker cookie_checker;
	struct pubkey_hashtable *peer_hashtable;
	struct index_hashtable *index_hashtable;
	struct allowedips peer_allowedips;
	struct mutex device_update_lock, socket_update_lock;
	struct list_head device_list, peer_list;
	/* Deferred FEC MTU policy: adaptive FEC may arm or disarm on the TX
	 * path, where dev_set_mtu() is impossible, so the recompute runs from
	 * process context here.
	 */
	struct work_struct fec_mtu_work;
	struct uwg_header_protection __rcu *header_protection;
	/* Bounds the cost of unknown-peer notifications: every event allocates
	 * a fresh ~8 KiB skb, which unauthenticated handshake initiations must
	 * not be able to drive unchecked.
	 */
	struct ratelimit_state unknown_peer_notify;
	struct jp_spec ispecs[5];
	u32_range_t init_header, resp_header, cookie_header, transport_header;
	u16_range_t content_padding_addition, max_handshake_attempts;
	u16_range_t rekey_after_time, rekey_timeout, reject_after_time, keepalive_timeout;
	atomic_t handshake_queue_len;
	unsigned int num_peers, device_update_gen;
	u32 fwmark;
	u16 init_padding, resp_padding, cookie_padding, transport_padding;
	u16 incoming_port;
	u16 jc, jmin, jmax;
	bool random_trailers, disable_cookies;
};

int uwg_device_init(void);
void uwg_device_uninit(void);

#endif /* _UWG_DEVICE_H */
