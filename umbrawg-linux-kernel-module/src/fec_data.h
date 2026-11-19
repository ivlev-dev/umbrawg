/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _UWG_FEC_DATA_H
#define _UWG_FEC_DATA_H

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
#define UWG_FEC_DATA_TX_DELAY_US 1000

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
