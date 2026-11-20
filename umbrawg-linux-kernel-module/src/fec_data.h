/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _UWG_FEC_DATA_H
#define _UWG_FEC_DATA_H

#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/skbuff.h>

struct uwg_peer;
struct uwg_device;
struct uwg_ext_fec_shard;
struct uwg_fec_tx;
struct uwg_fec_rx;

#define UWG_FEC_DATA_MAX_K 8
#define UWG_FEC_DATA_MAX_M 2
#define UWG_FEC_DATA_MAX_SHARDS (UWG_FEC_DATA_MAX_K + UWG_FEC_DATA_MAX_M)
#define UWG_FEC_DATA_SHARD_CAP 1900
#define UWG_FEC_DATA_SLOTS 16
#define UWG_FEC_DATA_BLOCK_TIMEOUT_US 5000
#define UWG_FEC_DATA_TX_DELAY_MIN_US 500
#define UWG_FEC_DATA_TX_DELAY_MAX_US 2000
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

void uwg_fec_adaptive_observe(struct uwg_peer *peer, u64 counter);

bool uwg_fec_mode_config(u32 mode, u8 *k, u8 *m, bool *adaptive);
bool uwg_fec_peer_tx_ready(const struct uwg_peer *peer);
bool uwg_fec_tx_push(struct uwg_peer *peer, struct sk_buff *skb,
		     struct sk_buff_head *out);
int uwg_fec_rx_shard(struct uwg_peer *peer,
		     const struct uwg_ext_fec_shard *shard,
		     struct sk_buff *skb, size_t offset, u64 keypair_id,
		     bool use_napi);

int uwg_peer_fec_sync(struct uwg_peer *peer);
int uwg_peer_fec_sync_device(struct uwg_device *uwg);
void uwg_peer_fec_release(struct uwg_peer *peer);
void uwg_peer_fec_rcu_free(struct uwg_peer *peer);
void uwg_fec_tx_free(struct uwg_fec_tx *tx);
void uwg_fec_rx_free(struct uwg_fec_rx *rx);

#endif /* _UWG_FEC_DATA_H */
