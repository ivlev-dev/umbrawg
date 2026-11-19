// SPDX-License-Identifier: GPL-2.0

#include "fec_data.h"
#include "device.h"
#include "ext.h"
#include "fec.h"
#include "peer.h"
#include "queueing.h"
#include "type.h"

#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/unaligned.h>

struct uwg_fec_tx {
	struct uwg_peer *peer;
	spinlock_t lock;
	struct timer_list timer;
	u8 k;
	u8 m;
	bool adaptive;
	bool adaptive_on;
	bool adaptive_valid;
	bool disabled;
	u64 adaptive_largest;
	u64 adaptive_base;
	u64 adaptive_received;
	u64 adaptive_observed;
	u32 adaptive_loss_q16;
	unsigned long adaptive_clean_since;
	u8 count;
	u16 lens[UWG_FEC_DATA_MAX_K];
	u8 *shards;
	u8 *block;
	u32 block_id;
};

struct uwg_fec_rx_block {
	u32 block_id;
	u16 shard_len;
	unsigned long deadline;
	u8 k;
	u8 m;
	u8 present;
	bool used;
	bool ready;
	bool have[UWG_FEC_DATA_MAX_SHARDS];
};

struct uwg_fec_rx {
	struct uwg_peer *peer;
	spinlock_t lock;
	struct timer_list timer;
	u8 k;
	u8 m;
	u8 total;
	u8 slots;
	bool adaptive;
	bool disabled;
	u8 *arena;
	struct uwg_fec_rx_block blocks[UWG_FEC_DATA_SLOTS];
	u32 next_id;
	bool have_next;
	u64 keypair_id;
	bool keypair_valid;
};

bool uwg_fec_mode_config(u32 mode, u8 *k, u8 *m, bool *adaptive)
{
	u8 data, parity;
	bool adapt = false;

	if (mode == UWG_FEC_MODE_OFF)
		return false;
	if (mode == UWG_FEC_MODE_ADAPTIVE) {
		data = 2;
		parity = 1;
		adapt = true;
	} else {
		data = (u8)(mode >> 8);
		parity = (u8)mode;
	}
	if (data < 1 || parity < 1 ||
	    data > UWG_FEC_DATA_MAX_K || parity > UWG_FEC_DATA_MAX_M)
		return false;
	if (k)
		*k = data;
	if (m)
		*m = parity;
	if (adaptive)
		*adaptive = adapt;
	return true;
}

static unsigned int uwg_fec_tx_limit(const struct uwg_peer *peer)
{
	int limit = (int)READ_ONCE(peer->device->dev->mtu) + 2 -
		    (UWG_EXT_HEADER_LEN + UWG_EXT_FEC_HEADER_LEN +
		     MESSAGE_PADDING_MULTIPLE);

	/* The shard budget has to cover the two byte packet length prefix,
	 * the ext and FEC shard headers, the payload, and the encryption
	 * padding, all of which are sent inside one underlay datagram sized
	 * by the TUN MTU.
	 */
	if (limit > UWG_FEC_DATA_SHARD_CAP)
		limit = UWG_FEC_DATA_SHARD_CAP;
	if (limit < 64)
		limit = 64;
	return (unsigned int)limit;
}

static void uwg_fec_adaptive_window_reset(struct uwg_fec_tx *tx, u64 counter)
{
	tx->adaptive_largest = counter;
	tx->adaptive_base = counter;
	tx->adaptive_received = 1;
	tx->adaptive_observed = 0;
	tx->adaptive_loss_q16 = 0;
	tx->adaptive_clean_since = 0;
}

void uwg_fec_adaptive_observe(struct uwg_peer *peer, u64 counter)
{
	struct uwg_fec_tx *tx;
	u64 expected, lost, loss_q16;

	rcu_read_lock();
	tx = rcu_dereference(peer->fec_tx);
	if (!tx || !tx->adaptive)
		goto out;
	spin_lock_bh(&tx->lock);
	if (!tx->adaptive_valid) {
		tx->adaptive_valid = true;
		uwg_fec_adaptive_window_reset(tx, counter);
		goto unlock;
	}
	if (counter < tx->adaptive_base) {
		/* Small backward jumps are reordering, but a huge one means
		 * the counters restarted after a rekey.
		 */
		if (tx->adaptive_base - counter > 1U << 20)
			uwg_fec_adaptive_window_reset(tx, counter);
		goto unlock;
	}
	if (counter > tx->adaptive_largest)
		tx->adaptive_largest = counter;
	tx->adaptive_received++;
	expected = tx->adaptive_largest - tx->adaptive_base + 1;
	if (expected < 256)
		goto unlock;
	if (unlikely(expected > 1U << 20)) {
		/* Drop an implausible gap instead of overflowing the estimate. */
		tx->adaptive_base = tx->adaptive_largest + 1;
		tx->adaptive_received = 0;
		goto unlock;
	}
	lost = expected > tx->adaptive_received ?
		expected - tx->adaptive_received : 0;
	loss_q16 = (u32)div_u64(lost << 16, expected);
	tx->adaptive_loss_q16 = (tx->adaptive_loss_q16 * 3 + loss_q16) / 4;
	tx->adaptive_observed += expected;
	tx->adaptive_base = tx->adaptive_largest + 1;
	tx->adaptive_received = 0;
	if (!tx->adaptive_on) {
		if (tx->adaptive_observed >= 1024 &&
		    tx->adaptive_loss_q16 > 655)
			tx->adaptive_on = true;
	} else if (tx->adaptive_loss_q16 < 131) {
		if (!tx->adaptive_clean_since)
			tx->adaptive_clean_since = jiffies;
		else if (time_after(jiffies,
				    tx->adaptive_clean_since + 5 * HZ))
			tx->adaptive_on = false;
	} else {
		tx->adaptive_clean_since = 0;
	}
unlock:
	spin_unlock_bh(&tx->lock);
out:
	rcu_read_unlock();
}

bool uwg_fec_peer_tx_ready(const struct uwg_peer *peer)
{
	u8 k, m;
	bool adaptive;

	if (!uwg_fec_mode_config(READ_ONCE(peer->device->fec_mode), &k, &m,
				 &adaptive))
		return false;
	if (!READ_ONCE(peer->caps.peer_valid))
		return false;
	if (!(READ_ONCE(peer->caps.peer.flags) & UWG_EXT_CAP_FEC))
		return false;
	/* A mismatched profile would make the receiver drop every shard. */
	if (READ_ONCE(peer->caps.peer.fec_k) != k ||
	    READ_ONCE(peer->caps.peer.fec_m) != m)
		return false;
	return true;
}

static void uwg_fec_tx_emit(struct uwg_fec_tx *tx, bool with_parity,
			    struct sk_buff_head *out)
{
	struct uwg_peer *peer = tx->peer;
	struct net_device *dev = peer->device->dev;
	unsigned int i, n = tx->count, shard_len = 0, total;
	u8 block_k, block_m;
	u32 block_id = tx->block_id;

	if (!n)
		return;

	for (i = 0; i < n; i++) {
		unsigned int len = (unsigned int)tx->lens[i] + 2;

		if (len > shard_len)
			shard_len = len;
	}
	if (shard_len < 2 || shard_len > UWG_FEC_DATA_SHARD_CAP)
		goto out;

	for (i = 0; i < n; i++) {
		unsigned int copy = (unsigned int)tx->lens[i] + 2;
		u8 *dst = tx->block + (size_t)i * shard_len;

		memcpy(dst, tx->shards + (size_t)i * UWG_FEC_DATA_SHARD_CAP,
		       copy);
		if (copy < shard_len)
			memset(dst + copy, 0, shard_len - copy);
	}

	block_k = with_parity ? tx->k : (u8)n;
	block_m = with_parity ? tx->m : 0;
	if (with_parity &&
	    uwg_fec_encode(tx->k, tx->m, shard_len, tx->block,
			   tx->block + (size_t)tx->k * shard_len)) {
		block_m = 0;
		block_k = (u8)n;
	}
	total = (unsigned int)block_k + block_m;

	for (i = 0; i < total; i++) {
		struct uwg_ext_fec_shard shard;
		struct sk_buff *skb;
		u8 *hdr;

		memset(&shard, 0, sizeof(shard));
		shard.block_id = block_id;
		shard.index = (u8)i;
		shard.k = block_k;
		shard.m = block_m;
		shard.flags = i >= block_k ? UWG_EXT_FEC_FLAG_PARITY : 0;
		shard.shard_len = (u16)shard_len;

		skb = alloc_skb(DATA_PACKET_HEAD_ROOM + UWG_EXT_HEADER_LEN +
					UWG_EXT_FEC_HEADER_LEN + shard_len,
				GFP_ATOMIC);
		if (unlikely(!skb)) {
			DEV_STATS_INC(dev, tx_dropped);
			continue;
		}
		skb_reserve(skb, DATA_PACKET_HEAD_ROOM);
		hdr = skb_put(skb, UWG_EXT_HEADER_LEN +
				   UWG_EXT_FEC_HEADER_LEN);
		if (unlikely(uwg_ext_build_fec_shard_header(
				     hdr, UWG_EXT_HEADER_LEN +
						  UWG_EXT_FEC_HEADER_LEN,
				     &shard) < 0)) {
			kfree_skb(skb);
			DEV_STATS_INC(dev, tx_dropped);
			continue;
		}
		skb_put_data(skb, tx->block + (size_t)i * shard_len,
			     shard_len);
		skb->dev = dev;
		/* Zero MTU makes the sender pad to the 16 byte block only
		 * instead of aligning the shard up to the TUN MTU, which would
		 * blow the underlay datagram budget.
		 */
		PACKET_CB(skb)->mtu = 0;
		PACKET_CB(skb)->ds = 0;
		PACKET_CB(skb)->is_keepalive = false;
		PACKET_CB(skb)->is_fec = true;
		PACKET_CB(skb)->pace_len = i ? 0 :
			total * (UWG_EXT_HEADER_LEN +
				 UWG_EXT_FEC_HEADER_LEN + shard_len);
		__skb_queue_tail(out, skb);
	}

out:
	tx->count = 0;
	tx->block_id = block_id + 1;
}

static bool uwg_fec_tx_push_locked(struct uwg_fec_tx *tx,
				   struct uwg_peer *peer, struct sk_buff *skb,
				   struct sk_buff_head *out)
{
	unsigned int plen = skb->len;
	unsigned int limit = uwg_fec_tx_limit(peer);
	u8 *slot;

	if (unlikely(tx->disabled))
		return false;
	if (plen + 2 > limit)
		return false;
	if (tx->count >= tx->k)
		return false;
	slot = tx->shards + (size_t)tx->count * UWG_FEC_DATA_SHARD_CAP;
	if (unlikely(skb_copy_bits(skb, 0, slot + 2, plen)))
		return false;
	put_unaligned_le16((u16)plen, slot);
	tx->lens[tx->count] = (u16)plen;
	tx->count++;
	if (tx->count == 1)
		mod_timer(&tx->timer,
			  jiffies + max_t(unsigned long, 1,
					  usecs_to_jiffies(
						  UWG_FEC_DATA_TX_DELAY_US)));
	if (tx->count == tx->k)
		uwg_fec_tx_emit(tx, true, out);
	return true;
}

static void uwg_fec_tx_timeout(struct timer_list *timer)
{
	struct uwg_fec_tx *tx = timer_container_of(tx, timer, timer);
	struct uwg_peer *peer = tx->peer;
	struct sk_buff_head frames;

	if (unlikely(READ_ONCE(peer->is_dead)))
		return;

	__skb_queue_head_init(&frames);
	spin_lock_bh(&tx->lock);
	if (!tx->disabled && tx->count)
		uwg_fec_tx_emit(tx, false, &frames);
	spin_unlock_bh(&tx->lock);
	if (!skb_queue_empty(&frames))
		uwg_packet_send_fec_frames(peer, &frames);
}

bool uwg_fec_tx_push(struct uwg_peer *peer, struct sk_buff *skb,
		     struct sk_buff_head *out)
{
	struct uwg_fec_tx *tx;
	bool consumed = false;

	if (!uwg_fec_peer_tx_ready(peer))
		return false;
	if (skb->len + 2 > uwg_fec_tx_limit(peer))
		return false;
	/* The shard payload is a byte copy of the plaintext packet taken before
	 * the regular send path finalizes checksums. Complete them first, or a
	 * receiver that verifies inner checksums (userspace) drops the packet.
	 * Done outside the FEC lock: skb_checksum_help may allocate.
	 */
	if (unlikely(skb->ip_summed == CHECKSUM_PARTIAL &&
		     skb_checksum_help(skb)))
		return false;

	rcu_read_lock();
	tx = rcu_dereference(peer->fec_tx);
	if (tx && tx->adaptive && !READ_ONCE(tx->adaptive_on)) {
		rcu_read_unlock();
		return false;
	}
	if (tx) {
		spin_lock_bh(&tx->lock);
		if (tx->count && skb->len + 2 > uwg_fec_tx_limit(peer))
			uwg_fec_tx_emit(tx, false, out);
		consumed = uwg_fec_tx_push_locked(tx, peer, skb, out);
		spin_unlock_bh(&tx->lock);
	}
	rcu_read_unlock();

	if (consumed)
		kfree_skb(skb);
	return consumed;
}

static u8 *uwg_fec_rx_slot(struct uwg_fec_rx *rx, unsigned int slot,
			   unsigned int index)
{
	return rx->arena + ((size_t)slot * rx->total + index) *
				   UWG_FEC_DATA_SHARD_CAP;
}

static void uwg_fec_rx_extract(struct uwg_fec_rx *rx, unsigned int slot,
			       bool present_only, struct sk_buff_head *out)
{
	struct uwg_fec_rx_block *blk = &rx->blocks[slot];
	struct net_device *dev = rx->peer->device->dev;
	unsigned int i;

	for (i = 0; i < blk->k; i++) {
		const u8 *p = uwg_fec_rx_slot(rx, slot, i);
		struct sk_buff *skb;
		u16 len;

		if (present_only && !blk->have[i])
			continue;
		len = get_unaligned_le16(p);
		if ((unsigned int)len + 2 > blk->shard_len)
			continue;
		skb = netdev_alloc_skb(dev, len);
		if (unlikely(!skb)) {
			DEV_STATS_INC(dev, rx_dropped);
			continue;
		}
		skb_put_data(skb, p + 2, len);
		__skb_queue_tail(out, skb);
	}
}

static void uwg_fec_rx_arm(struct uwg_fec_rx *rx)
{
	unsigned long deadline = 0;
	unsigned int i;
	bool any = false;

	if (unlikely(rx->disabled))
		return;
	for (i = 0; i < rx->slots; i++) {
		struct uwg_fec_rx_block *blk = &rx->blocks[i];

		if (!blk->used)
			continue;
		if (!any || time_before(blk->deadline, deadline)) {
			deadline = blk->deadline;
			any = true;
		}
	}
	if (any)
		timer_reduce(&rx->timer, deadline);
}

static void uwg_fec_rx_drain(struct uwg_fec_rx *rx, struct sk_buff_head *out)
{
	unsigned long now = jiffies;

	for (;;) {
		struct uwg_fec_rx_block *blk = NULL;
		unsigned int i, slot = rx->slots;
		unsigned int oldest = rx->slots;
		unsigned long oldest_deadline = 0;

		if (!rx->have_next)
			break;

		for (i = 0; i < rx->slots; i++) {
			if (rx->blocks[i].used &&
			    rx->blocks[i].block_id == rx->next_id) {
				slot = i;
				break;
			}
		}
		if (slot < rx->slots) {
			blk = &rx->blocks[slot];
			if (blk->ready ||
			    time_after_eq(now, blk->deadline)) {
				uwg_fec_rx_extract(rx, slot, !blk->ready,
						   out);
				blk->used = false;
				rx->next_id++;
				continue;
			}
			break;
		}

		for (i = 0; i < rx->slots; i++) {
			if (!rx->blocks[i].used)
				continue;
			if (oldest == rx->slots ||
			    time_before(rx->blocks[i].deadline,
					oldest_deadline)) {
				oldest = i;
				oldest_deadline = rx->blocks[i].deadline;
			}
		}
		if (oldest == rx->slots)
			break;
		if (!time_after_eq(now, oldest_deadline))
			break;
		rx->next_id = rx->blocks[oldest].block_id;
	}

	uwg_fec_rx_arm(rx);
}

static void uwg_fec_rx_deliver(struct uwg_peer *peer,
			       struct sk_buff_head *out, bool use_napi)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(out)) != NULL)
		uwg_packet_deliver_inner(peer, skb, 0, use_napi);
}

static void uwg_fec_rx_timeout(struct timer_list *timer)
{
	struct uwg_fec_rx *rx = timer_container_of(rx, timer, timer);
	struct uwg_peer *peer = rx->peer;
	struct sk_buff_head out;

	if (unlikely(READ_ONCE(peer->is_dead)))
		return;

	__skb_queue_head_init(&out);
	spin_lock_bh(&rx->lock);
	if (likely(!rx->disabled))
		uwg_fec_rx_drain(rx, &out);
	spin_unlock_bh(&rx->lock);
	uwg_fec_rx_deliver(peer, &out, false);
}

static void uwg_fec_rx_reset_locked(struct uwg_fec_rx *rx, u64 keypair_id)
{
	unsigned int i;

	for (i = 0; i < rx->slots; i++)
		rx->blocks[i].used = false;
	rx->have_next = false;
	rx->keypair_id = keypair_id;
	rx->keypair_valid = true;
}

int uwg_fec_rx_shard(struct uwg_peer *peer,
		     const struct uwg_ext_fec_shard *shard,
		     struct sk_buff *skb, size_t offset, u64 keypair_id,
		     bool use_napi)
{
	struct uwg_fec_rx *rx;
	struct uwg_fec_rx_block *blk;
	struct sk_buff_head out;
	unsigned int i, slot = UWG_FEC_DATA_SLOTS;
	bool invalid = false;
	int ret = 0;

	if (shard->shard_len < 2 ||
	    shard->shard_len > UWG_FEC_DATA_SHARD_CAP)
		return -EINVAL;

	rcu_read_lock();
	rx = rcu_dereference(peer->fec_rx);
	if (!rx || !READ_ONCE(peer->caps.peer_valid) ||
	    !(READ_ONCE(peer->caps.peer.flags) & UWG_EXT_CAP_FEC)) {
		ret = -EINVAL;
		goto out_rcu;
	}
	if (shard->m == 0) {
		if (!shard->k || shard->k > rx->k)
			invalid = true;
	} else if (shard->k != rx->k || shard->m != rx->m) {
		invalid = true;
	}
	if (invalid) {
		ret = -EINVAL;
		goto out_rcu;
	}

	__skb_queue_head_init(&out);
	spin_lock_bh(&rx->lock);
	if (unlikely(rx->disabled)) {
		ret = -EINVAL;
		goto out_unlock;
	}
	if (!rx->keypair_valid || rx->keypair_id != keypair_id)
		uwg_fec_rx_reset_locked(rx, keypair_id);
	if (!rx->have_next) {
		rx->next_id = shard->block_id;
		rx->have_next = true;
	}
	if ((s32)(shard->block_id - rx->next_id) < 0)
		goto out_unlock;

	for (i = 0; i < rx->slots; i++) {
		if (rx->blocks[i].used &&
		    rx->blocks[i].block_id == shard->block_id) {
			slot = i;
			break;
		}
	}
	if (slot == UWG_FEC_DATA_SLOTS) {
		for (i = 0; i < rx->slots; i++) {
			if (!rx->blocks[i].used) {
				slot = i;
				break;
			}
		}
	}
	if (slot == UWG_FEC_DATA_SLOTS) {
		uwg_fec_rx_drain(rx, &out);
		for (i = 0; i < rx->slots; i++) {
			if (!rx->blocks[i].used) {
				slot = i;
				break;
			}
		}
	}
	if (slot == UWG_FEC_DATA_SLOTS) {
		unsigned int oldest = 0;

		for (i = 1; i < rx->slots; i++) {
			if (time_before(rx->blocks[i].deadline,
					rx->blocks[oldest].deadline))
				oldest = i;
		}
		uwg_fec_rx_extract(rx, oldest, !rx->blocks[oldest].ready,
				   &out);
		if (rx->blocks[oldest].block_id == rx->next_id)
			rx->next_id++;
		rx->blocks[oldest].used = false;
		slot = oldest;
	}

	blk = &rx->blocks[slot];
	if (!blk->used) {
		blk->used = true;
		blk->ready = false;
		blk->block_id = shard->block_id;
		blk->k = shard->k;
		blk->m = shard->m;
		blk->shard_len = shard->shard_len;
		blk->present = 0;
		blk->deadline = jiffies + max_t(unsigned long, 1,
						usecs_to_jiffies(
						 UWG_FEC_DATA_BLOCK_TIMEOUT_US));
		memset(blk->have, 0, sizeof(blk->have));
	} else if (blk->k != shard->k || blk->m != shard->m ||
		   blk->shard_len != shard->shard_len) {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (!blk->have[shard->index]) {
		if (unlikely(skb_copy_bits(skb, offset,
					   uwg_fec_rx_slot(rx, slot,
							   shard->index),
					   shard->shard_len))) {
			ret = -EINVAL;
			goto out_unlock;
		}
		blk->have[shard->index] = true;
		blk->present++;
	}

	if (blk->m == 0) {
		if (blk->present == blk->k)
			blk->ready = true;
	} else if (blk->present >= blk->k) {
		u8 *shards[UWG_FEC_DATA_MAX_SHARDS];
		bool present[UWG_FEC_DATA_MAX_SHARDS];
		unsigned int total = blk->k + blk->m;

		for (i = 0; i < total; i++) {
			shards[i] = uwg_fec_rx_slot(rx, slot, i);
			present[i] = blk->have[i];
		}
		if (!uwg_fec_decode(blk->k, blk->m, blk->shard_len,
				    shards, present))
			blk->ready = true;
		else
			blk->used = false;
	}

	uwg_fec_rx_drain(rx, &out);
out_unlock:
	spin_unlock_bh(&rx->lock);
	rcu_read_unlock();
	uwg_fec_rx_deliver(peer, &out, use_napi);
	return ret;
out_rcu:
	rcu_read_unlock();
	return ret;
}

static struct uwg_fec_tx *uwg_fec_tx_alloc(struct uwg_peer *peer, u8 k, u8 m,
					   bool adaptive)
{
	struct uwg_fec_tx *tx;

	tx = kzalloc(sizeof(*tx), GFP_KERNEL);
	if (!tx)
		return NULL;
	tx->shards = kvzalloc((size_t)k * UWG_FEC_DATA_SHARD_CAP,
			      GFP_KERNEL);
	tx->block = kvzalloc((size_t)(k + m) * UWG_FEC_DATA_SHARD_CAP,
			     GFP_KERNEL);
	if (!tx->shards || !tx->block) {
		uwg_fec_tx_free(tx);
		return NULL;
	}
	tx->peer = peer;
	tx->k = k;
	tx->m = m;
	tx->adaptive = adaptive;
	tx->block_id = 0;
	spin_lock_init(&tx->lock);
	timer_setup(&tx->timer, uwg_fec_tx_timeout, 0);
	return tx;
}

static struct uwg_fec_rx *uwg_fec_rx_alloc(struct uwg_peer *peer, u8 k, u8 m,
					   bool adaptive)
{
	struct uwg_fec_rx *rx;

	rx = kzalloc(sizeof(*rx), GFP_KERNEL);
	if (!rx)
		return NULL;
	rx->total = k + m;
	rx->slots = (u8)clamp_t(size_t,
				65536 / ((size_t)rx->total *
					 UWG_FEC_DATA_SHARD_CAP),
				4, UWG_FEC_DATA_SLOTS);
	rx->arena = kvzalloc((size_t)rx->slots * rx->total *
				     UWG_FEC_DATA_SHARD_CAP,
			     GFP_KERNEL);
	if (!rx->arena) {
		kfree(rx);
		return NULL;
	}
	rx->peer = peer;
	rx->k = k;
	rx->m = m;
	rx->adaptive = adaptive;
	spin_lock_init(&rx->lock);
	timer_setup(&rx->timer, uwg_fec_rx_timeout, 0);
	return rx;
}

void uwg_fec_tx_free(struct uwg_fec_tx *tx)
{
	if (!tx)
		return;
	kvfree(tx->shards);
	kvfree(tx->block);
	kfree(tx);
}

void uwg_fec_rx_free(struct uwg_fec_rx *rx)
{
	if (!rx)
		return;
	kvfree(rx->arena);
	kfree(rx);
}

static void uwg_fec_mark_resend(struct uwg_peer *peer)
{
	spin_lock_bh(&peer->caps.lock);
	peer->caps.send_attempts = 0;
	peer->caps.next_send = 0;
	WRITE_ONCE(peer->caps.resend, true);
	spin_unlock_bh(&peer->caps.lock);
}

int uwg_peer_fec_sync(struct uwg_peer *peer)
{
	struct uwg_device *uwg = peer->device;
	struct uwg_fec_tx *tx;
	struct uwg_fec_rx *rx;
	u8 k = 0, m = 0;
	bool adaptive = false;
	bool want;

	want = uwg_fec_mode_config(READ_ONCE(uwg->fec_mode), &k, &m,
				   &adaptive);
	tx = rcu_dereference_protected(peer->fec_tx, 1);
	rx = rcu_dereference_protected(peer->fec_rx, 1);

	if (want && tx && rx && tx->k == k && tx->m == m &&
	    rx->k == k && rx->m == m && tx->adaptive == adaptive &&
	    rx->adaptive == adaptive)
		return 0;

	if (!want && !tx && !rx)
		return 0;

	uwg_peer_fec_release(peer);
	uwg_fec_mark_resend(peer);
	if (!want) {
		uwg_ext_maybe_send_caps(peer);
		return 0;
	}

	tx = uwg_fec_tx_alloc(peer, k, m, adaptive);
	if (!tx)
		return -ENOMEM;
	rx = uwg_fec_rx_alloc(peer, k, m, adaptive);
	if (!rx) {
		uwg_fec_tx_free(tx);
		return -ENOMEM;
	}
	rcu_assign_pointer(peer->fec_tx, tx);
	rcu_assign_pointer(peer->fec_rx, rx);
	uwg_ext_maybe_send_caps(peer);
	return 0;
}

int uwg_peer_fec_sync_device(struct uwg_device *uwg)
{
	struct uwg_peer *peer;
	int ret = 0;

	lockdep_assert_held(&uwg->device_update_lock);

	list_for_each_entry(peer, &uwg->peer_list, peer_list) {
		if (unlikely(uwg_peer_fec_sync(peer)))
			ret = -ENOMEM;
	}
	return ret;
}

void uwg_peer_fec_release(struct uwg_peer *peer)
{
	struct uwg_fec_tx *tx = rcu_dereference_protected(peer->fec_tx, 1);
	struct uwg_fec_rx *rx = rcu_dereference_protected(peer->fec_rx, 1);

	if (!tx && !rx)
		return;
	/* Unpublish first and let every in-flight reader finish: they may
	 * still arm a timer, and the shard timeout re-arms itself, so the
	 * timers can only be shut down once readers are gone.
	 */
	RCU_INIT_POINTER(peer->fec_tx, NULL);
	RCU_INIT_POINTER(peer->fec_rx, NULL);
	synchronize_net();
	if (tx) {
		spin_lock_bh(&tx->lock);
		tx->disabled = true;
		spin_unlock_bh(&tx->lock);
		timer_shutdown_sync(&tx->timer);
	}
	if (rx) {
		spin_lock_bh(&rx->lock);
		rx->disabled = true;
		spin_unlock_bh(&rx->lock);
		timer_shutdown_sync(&rx->timer);
	}
	uwg_fec_tx_free(tx);
	uwg_fec_rx_free(rx);
}

void uwg_peer_fec_rcu_free(struct uwg_peer *peer)
{
	struct uwg_fec_tx *tx = rcu_dereference_protected(peer->fec_tx, 1);
	struct uwg_fec_rx *rx = rcu_dereference_protected(peer->fec_rx, 1);

	/* Runs from an RCU callback, so no sleeping: release() already shut
	 * the timers down, and timer_delete is safe in softirq context.
	 */
	if (tx) {
		timer_delete(&tx->timer);
		uwg_fec_tx_free(tx);
	}
	if (rx) {
		timer_delete(&rx->timer);
		uwg_fec_rx_free(rx);
	}
}
