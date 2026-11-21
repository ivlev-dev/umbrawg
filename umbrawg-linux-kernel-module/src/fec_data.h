/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _UWG_FEC_DATA_H
#define _UWG_FEC_DATA_H

#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/skbuff.h>

#include "ext.h"
#include "messages.h"

struct uwg_peer;
struct uwg_device;
struct uwg_ext_fec_shard;
struct uwg_fec_tx;
struct uwg_fec_rx;

/* Bounds of UWGDEVICE_A_UNDERLAY_MTU. The lower bound is the classic IPv4
 * minimum reassembly buffer, so a policy can never shrink the tunnel MTU
 * below what any IPv4 path is required to carry.
 */
#define UWG_UNDERLAY_MTU_DEFAULT 1500
#define UWG_UNDERLAY_MTU_MIN 576
#define UWG_UNDERLAY_MTU_MAX 65535

/* Worst case outer headers of one underlay datagram: IPv6 (40) + UDP (8).
 * IPv4 is 20 bytes shorter but the policy must hold for every peer.
 */
#define UWG_FEC_UNDERLAY_IP_UDP_OVERHEAD 48

/* Outer padding of a FEC shard: calculate_skb_padding() aligns the plaintext
 * up to MESSAGE_PADDING_MULTIPLE and may add up to one block minus one byte
 * of random tail on top. encrypt_packet() additionally caps the random
 * transport trailer of a FEC frame at UWG_FEC_SHARD_TRAILER_MAX, because the
 * window-derived trailer would otherwise be sized by the TUN MTU and could
 * outgrow a whole underlay datagram.
 */
#define UWG_FEC_SHARD_TRAILER_MAX (MESSAGE_PADDING_MULTIPLE - 1)
#define UWG_FEC_SHARD_PADDING_MAX (2 * (MESSAGE_PADDING_MULTIPLE - 1))

/* Exact overhead of one FEC shard inside one underlay datagram, excluding the
 * inner packet itself: 48 bytes of IP/UDP, the message header and auth tag
 * (MESSAGE_MINIMUM_LENGTH), both extension headers, the two byte shard length
 * prefix and the worst case padding above. uwg_fec_mtu_selftest() keeps this
 * in sync with the builder in uwg_fec_tx_emit(). The obfuscation prefix S4
 * (`transport_padding`) is not part of this constant because it is a runtime
 * policy value; callers pass it to uwg_fec_allowed_inner()/uwg_fec_target_mtu()
 * and it is subtracted from the same budget.
 */
#define UWG_FEC_SHARD_WIRE_OVERHEAD \
	(UWG_FEC_UNDERLAY_IP_UDP_OVERHEAD + MESSAGE_MINIMUM_LENGTH + \
	 UWG_EXT_HEADER_LEN + UWG_EXT_FEC_HEADER_LEN + 2 + \
	 UWG_FEC_SHARD_PADDING_MAX)

unsigned int uwg_fec_allowed_inner(unsigned int underlay_mtu,
				   unsigned int underlay_padding);
unsigned int uwg_fec_underlay_payload(const struct uwg_device *uwg);
unsigned int uwg_fec_target_mtu(unsigned int underlay_mtu,
				unsigned int base_mtu, bool fec_on,
				unsigned int underlay_padding);
void uwg_fec_refresh_mtu(struct uwg_device *uwg);
int uwg_fec_mtu_selftest(void);

#define UWG_FEC_DATA_MAX_K 8
#define UWG_FEC_DATA_MAX_M 2
#define UWG_FEC_DATA_MAX_SHARDS (UWG_FEC_DATA_MAX_K + UWG_FEC_DATA_MAX_M)
#define UWG_FEC_DATA_SHARD_CAP 1900
#define UWG_FEC_DATA_SLOTS 16
#define UWG_FEC_DATA_BLOCK_TIMEOUT_US 5000
/* Partial-block flush delay. A sparse stream cannot fill k, so the first
 * packet schedules a flush; the window only has to be wide enough for
 * back-to-back packets of one burst to share a block. It used to be
 * 0.5..2 ms, but it was applied with a jiffies timer, which can only fire
 * on a tick: every sparse packet paid a full tick (1 ms at HZ=1000, up to
 * 10 ms at HZ=100) plus the workqueue hop, i.e. the classic 4-5 ms FEC RTT
 * penalty. The flush is a hrtimer now, so the window below is the real cost.
 * 0.15..0.45 ms keeps a burst together and leaves the round trip near 1 ms.
 */
#define UWG_FEC_DATA_TX_DELAY_MIN_US 150
#define UWG_FEC_DATA_TX_DELAY_MAX_US 450
/* Random tail added to every shard of a block: it has to stay below the tx
 * limit and is the same for all shards, as Reed-Solomon requires.
 */
#define UWG_FEC_DATA_SHARD_SLACK 32

/* Local FEC observability, per peer. The update sites run on the TX emit and
 * the RX shard paths, which take different locks, so the counters are atomic
 * and are only read through the fill helpers below. Nothing here changes the
 * wire format; exporting these over netlink is a separate step.
 */
struct uwg_fec_counters {
	atomic64_t blocks_encoded;
	atomic64_t shards_sent;
	atomic64_t blocks_decoded;
	atomic64_t packets_recovered;
	atomic64_t decode_fail;
	atomic64_t dropped_bounds;
	atomic64_t dropped_disabled;
};

struct uwg_fec_stats {
	u64 blocks_encoded;
	u64 shards_sent;
	u64 blocks_decoded;
	u64 packets_recovered;
	u64 decode_fail;
	u64 dropped_bounds;
	u64 dropped_disabled;
};

void uwg_fec_stats_fill(const struct uwg_peer *peer, struct uwg_fec_stats *stats);
void uwg_fec_stats_fill_device(struct uwg_device *uwg,
			       struct uwg_fec_stats *stats);

void uwg_fec_adaptive_observe(struct uwg_peer *peer, u64 counter,
			      u64 keypair_id);

bool uwg_fec_mode_config(u32 mode, u8 *k, u8 *m, bool *adaptive);
bool uwg_fec_peer_tx_ready(const struct uwg_peer *peer);
bool uwg_fec_tx_push(struct uwg_peer *peer, struct sk_buff *skb,
		     struct sk_buff_head *out);
int uwg_fec_rx_shard(struct uwg_peer *peer,
		     const struct uwg_ext_fec_shard *shard,
		     struct sk_buff *skb, size_t offset, u64 keypair_id,
		     bool use_napi);

int uwg_peer_fec_sync(struct uwg_peer *peer);
int uwg_peer_fec_sync_device(struct uwg_device *uwg, u32 mode);
void uwg_peer_fec_release(struct uwg_peer *peer);
void uwg_peer_fec_rcu_free(struct uwg_peer *peer);
void uwg_fec_tx_free(struct uwg_fec_tx *tx);
void uwg_fec_rx_free(struct uwg_fec_rx *rx);

#endif /* _UWG_FEC_DATA_H */
