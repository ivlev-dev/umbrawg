/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _UWG_PEER_H
#define _UWG_PEER_H

#include "device.h"
#include "ext.h"
#include "fec_data.h"
#include "messages.h"
#include "noise.h"
#include "cookie.h"
#include "type.h"
#include "uapi/umbrawg.h"

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <net/dst_cache.h>

struct uwg_device;
struct uwg_fec_tx;
struct uwg_fec_rx;

struct endpoint {
	union {
		struct sockaddr_inet addr;     /* Large enough for both address families */
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	};
	union {
		struct {
			struct in_addr src4;
			/* Essentially the same as addr6->scope_id */
			int src_if4;
		};
		struct in6_addr src6;
	};
};

struct uwg_peer {
	struct uwg_device *device;
	struct prev_queue tx_queue, rx_queue;
	struct sk_buff_head staged_packet_queue;
	int serial_work_cpu;
	bool is_dead;
	bool timer_need_another_keepalive;
	bool sent_lastminute_handshake;
	struct noise_keypairs keypairs;
	struct endpoint endpoint;
	struct dst_cache endpoint_cache;
	rwlock_t endpoint_lock;
	struct noise_handshake handshake;
	atomic64_t last_sent_handshake;
	struct work_struct transmit_handshake_work, clear_peer_work, transmit_packet_work;
	struct cookie latest_cookie;
	struct hlist_node pubkey_hash;
	atomic64_t rx_bytes, tx_bytes;
	struct timer_list timer_retransmit_handshake, timer_send_keepalive;
	struct timer_list timer_new_handshake, timer_zero_key_material;
	struct timer_list timer_persistent_keepalive, timer_send_caps;
	/* jiffies of the last *data* (or control) frame we sent, and of the
	 * moment the keepalive timer was armed. The timer is no longer
	 * cancelled on every send: that cost a timer-base lock per batch and,
	 * because the next received packet then re-armed it, a mod_timer per
	 * data packet. The expiry compares these stamps instead. Keepalives
	 * themselves do not update last_data_tx, so an idle downlink still
	 * emits one per keepalive_timeout, exactly like before.
	 *
	 * Kept next to the timers on purpose: this is written on every TX
	 * batch, and the receive path reads is_dead per packet from the top of
	 * the struct -- sharing that cacheline would invalidate it on every
	 * send (measured as a ~7% loss at 50 peers).
	 */
	unsigned long keepalive_armed;
	unsigned long last_data_tx;
	unsigned int timer_handshake_attempts;
	unsigned int max_handshake_attempts;
	u32 persistent_keepalive_interval;
	enum uwg_cipher cipher;
	struct timespec64 walltime_last_handshake;
	struct kref refcount;
	struct rcu_head rcu;
	struct list_head peer_list;
	struct list_head allowedips_list;
	struct napi_struct napi;
	u64 internal_id;
	atomic_t jp_packet_counter;
	unsigned int udp_window;
	struct uwg_peer_caps caps;
	struct uwg_fec_tx __rcu *fec_tx;
	struct uwg_fec_rx __rcu *fec_rx;
	struct uwg_fec_counters fec_counters;
	/* Next FEC block id for this peer. It lives outside uwg_fec_tx so a
	 * profile change that replaces the TX state does not restart the
	 * sequence: the receiver keeps its block clock across the change and
	 * would drop every restarted id as stale.
	 */
	atomic_t fec_block_id;
};

struct uwg_peer *uwg_peer_create(struct uwg_device *uwg,
			       const u8 public_key[NOISE_PUBLIC_KEY_LEN],
			       const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN]);

int uwg_peer_fec_sync(struct uwg_peer *peer);
int uwg_peer_fec_sync_device(struct uwg_device *uwg, u32 mode);
void uwg_peer_fec_release(struct uwg_peer *peer);

struct uwg_peer *__must_check uwg_peer_get_maybe_zero(struct uwg_peer *peer);
static inline struct uwg_peer *uwg_peer_get(struct uwg_peer *peer)
{
	kref_get(&peer->refcount);
	return peer;
}
void uwg_peer_put(struct uwg_peer *peer);
void uwg_peer_remove(struct uwg_peer *peer);
void uwg_peer_remove_all(struct uwg_device *uwg);

int uwg_peer_init(void);
void uwg_peer_uninit(void);

static inline void uwg_peer_reset_last_sent_handshake(struct uwg_peer *peer)
{
	u16 timeout = !u16_range_is_zero(peer->device->rekey_timeout) ? u16_range_lo(peer->device->rekey_timeout) : REKEY_TIMEOUT;
	atomic64_set(&peer->last_sent_handshake, ktime_get_coarse_boottime_ns() -
				       (u64)(timeout + 1) * NSEC_PER_SEC);
}

/* Minimum room kept for the random trailer. A trailer derived only from the
 * observed window degenerates to zero for datagrams as large as the window,
 * i.e. exactly for full-MTU traffic, which then has a constant size. A few
 * random bytes below this floor are preferable to that tell.
 */
#define UWG_TRAILER_RANDOM_MIN 16

/* A peer can inflate our egress padding by sending an oversized datagram: the
 * learned UDP window is the exclusive upper bound of the random trailer, so an
 * unchecked window would let a peer make us emit tens of kilobytes per packet.
 * The window is capped at what a full-MTU datagram of this device plus the
 * fixed underlay overhead -- the noise message header, the configured
 * transport padding and the IP/UDP headers -- can legitimately measure.
 */
#define UWG_UDP_WINDOW_OVERHEAD (MESSAGE_MINIMUM_LENGTH + 128)
#define UWG_UDP_WINDOW_HARD_MAX 65535U

static inline unsigned int uwg_peer_udp_window_max(const struct uwg_device *uwg)
{
	unsigned int max = READ_ONCE(uwg->dev->mtu) +
			   READ_ONCE(uwg->transport_padding) +
			   UWG_UDP_WINDOW_OVERHEAD;
	unsigned int underlay = uwg_fec_underlay_payload(uwg);

	/* The window is measured on the whole datagram, so it must leave room
	 * for the underlay IP/UDP headers: a trailer that reaches the window
	 * would otherwise push the packet past the path MTU.
	 */
	if (max > underlay)
		max = underlay;
	if (max > UWG_UDP_WINDOW_HARD_MAX)
		max = UWG_UDP_WINDOW_HARD_MAX;
	return max;
}

static inline unsigned int uwg_peer_skb_random_trailer(struct uwg_peer *peer,
									struct uwg_device *uwg, unsigned int size)
{
	unsigned int udp_window = peer
		? READ_ONCE(peer->udp_window)
		: DEFAULT_UDP_WINDOW;
	unsigned int room;

	if (!uwg->random_trailers)
		return 0;

	room = udp_window > size ? udp_window - size : 0;
	if (room < UWG_TRAILER_RANDOM_MIN)
		room = UWG_TRAILER_RANDOM_MIN;
	return get_random_u32_below(room);
}

static inline unsigned int uwg_peer_skb_randomize_padding_addition(struct uwg_peer *peer,
									  			struct uwg_device *uwg, unsigned int size)
{
	unsigned int udp_window = peer
		? READ_ONCE(peer->udp_window)
		: DEFAULT_UDP_WINDOW;
	u16 add, space;

	if (udp_window < size)
		return 0;

	add = u16_range_pick_one(uwg->content_padding_addition);
	space = udp_window - size;
	return min(add, space);
}

/*
 * Cheap gate for uwg_ext_maybe_send_caps() on the per-packet receive path.
 *
 * With the extension switched off and no advertisement owed, the callee
 * returns immediately -- but only after taking the peer caps lock and reading
 * the clock, twice per data packet. This predicate is the exact set of
 * conditions under which the callee can do anything at all: the local profile
 * is advertised while FEC is on, and a revoke is due while the peer has
 * shown extension traffic or an answer/retry is pending. Nothing else in the
 * callee has a side effect, so skipping it here is behaviourally identical.
 */
static inline bool uwg_peer_caps_may_send(const struct uwg_peer *peer)
{
	return READ_ONCE(peer->device->fec_mode) != UWG_FEC_MODE_OFF ||
	       READ_ONCE(peer->caps.extension_seen) ||
	       READ_ONCE(peer->caps.resend) ||
	       READ_ONCE(peer->caps.retry);
}

#endif /* _UWG_PEER_H */
