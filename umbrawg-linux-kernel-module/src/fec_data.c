// SPDX-License-Identifier: GPL-2.0

#include "fec_data.h"
#include "device.h"
#include "ext.h"
#include "fec.h"
#include "peer.h"
#include "queueing.h"
#include "timers.h"
#include "type.h"

#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/netdevice.h>
#include <linux/random.h>
#include <linux/rtnetlink.h>
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
	unsigned long adaptive_segment_start;
	u8 count;
	u16 lens[UWG_FEC_DATA_MAX_K];
	u8 *shards;
	u8 *block;
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

unsigned int uwg_fec_allowed_inner(unsigned int underlay_mtu)
{
	if (underlay_mtu <= UWG_FEC_SHARD_WIRE_OVERHEAD)
		return 0;
	return underlay_mtu - UWG_FEC_SHARD_WIRE_OVERHEAD;
}

unsigned int uwg_fec_underlay_payload(const struct uwg_device *uwg)
{
	unsigned int underlay = READ_ONCE(uwg->underlay_mtu);

	if (underlay <= UWG_FEC_UNDERLAY_IP_UDP_OVERHEAD)
		return 0;
	return underlay - UWG_FEC_UNDERLAY_IP_UDP_OVERHEAD;
}

/* MTU the device should run at. With FEC on it is the largest inner packet
 * that still fits one shard datagram, and never above the base MTU the user
 * chose; with FEC off it is exactly that base. The 576 floor keeps ICMPv6 and
 * IPv4 reassembly working even when the underlay is tiny; the shard limit then
 * falls back to legacy for packets above the underlay budget.
 */
unsigned int uwg_fec_target_mtu(unsigned int underlay_mtu, unsigned int base_mtu,
				bool fec_on)
{
	unsigned int allowed, target;

	if (!fec_on)
		return base_mtu;

	allowed = uwg_fec_allowed_inner(underlay_mtu);
	/* Above the shard cap every packet would take the legacy path. */
	if (allowed > UWG_FEC_DATA_SHARD_CAP - 2)
		allowed = UWG_FEC_DATA_SHARD_CAP - 2;
	target = min(base_mtu, allowed);
	if (target < UWG_UNDERLAY_MTU_MIN)
		target = UWG_UNDERLAY_MTU_MIN;
	return target;
}

void uwg_fec_refresh_mtu(struct uwg_device *uwg)
{
	struct net_device *dev = uwg->dev;
	unsigned int base = READ_ONCE(uwg->fec_base_mtu);
	unsigned int cur_mtu = READ_ONCE(dev->mtu);
	unsigned int target;
	bool fec_on;
	int ret;

	fec_on = uwg_fec_mode_config(READ_ONCE(uwg->fec_mode), NULL, NULL, NULL);

	/* dev_set_mtu() is only allowed under rtnl: every caller (the netlink
	 * SET_DEVICE path, which also covers peer creation) holds it.
	 */
	ASSERT_RTNL();

	/* The MTU no longer matches the one programmed by the last refresh, so
	 * the operator changed it by hand (`ip link set mtu`). Adopt it as the
	 * new base instead of silently reverting their choice; the FEC policy
	 * is then applied to it.
	 */
	if (cur_mtu != READ_ONCE(uwg->fec_applied_mtu))
		base = cur_mtu;

	target = uwg_fec_target_mtu(READ_ONCE(uwg->underlay_mtu), base, fec_on);
	if (target != cur_mtu) {
		ret = dev_set_mtu(dev, (int)target);
		if (ret) {
			/* Keep the old MTU: FEC still works for packets that
			 * fit, the rest falls back to the legacy path.
			 */
			net_warn_ratelimited(
				"%s: Could not apply the FEC MTU %u: %d\n",
				dev->name, target, ret);
			target = cur_mtu;
		}
	}
	WRITE_ONCE(uwg->fec_base_mtu, base);
	WRITE_ONCE(uwg->fec_applied_mtu, target);
}

static unsigned int uwg_fec_tx_limit(const struct uwg_peer *peer)
{
	/* uwg_fec_refresh_mtu() already lowered the device MTU so that a
	 * full-size inner packet plus the two byte shard length prefix fits
	 * one shard datagram. The wire overhead is therefore not subtracted
	 * again here; the min() only matters when the policy could not apply
	 * (manual MTU after the last refresh, or a failed dev_set_mtu).
	 */
	struct uwg_device *uwg = peer->device;
	int limit = (int)min_t(unsigned int,
			       READ_ONCE(uwg->dev->mtu),
			       uwg_fec_allowed_inner(
				       READ_ONCE(uwg->underlay_mtu))) + 2;

	if (limit > UWG_FEC_DATA_SHARD_CAP)
		limit = UWG_FEC_DATA_SHARD_CAP;
	if (limit < 64)
		limit = 64;
	return (unsigned int)limit;
}

/* Adaptive FEC decides from the receive-side transport counter. A window is
 * only closed after it had time to settle: on a clean link with reordering a
 * packet arrives late but still inside the window and is counted, while a
 * genuinely lost counter never fills its slot. Evaluating on a fixed packet
 * count (the old 256 counter window) closed the window a few hundred
 * microseconds after a gap opened, so 25% netem reordering on a fast link
 * looked like massive loss and adaptive switched itself on. The segment is
 * therefore bounded by both a time and a counter ceiling.
 */
#define UWG_FEC_ADAPTIVE_MIN_WINDOW 256
#define UWG_FEC_ADAPTIVE_MAX_WINDOW (1U << 24)
#define UWG_FEC_ADAPTIVE_SETTLE_JIFFIES HZ

static void uwg_fec_adaptive_window_reset(struct uwg_fec_tx *tx, u64 counter,
					  unsigned long now)
{
	tx->adaptive_largest = counter;
	tx->adaptive_base = counter;
	tx->adaptive_received = 1;
	tx->adaptive_observed = 0;
	tx->adaptive_loss_q16 = 0;
	tx->adaptive_clean_since = 0;
	tx->adaptive_segment_start = now;
}

static void uwg_fec_adaptive_observe_locked(struct uwg_fec_tx *tx, u64 counter,
					    unsigned long now)
{
	u64 expected, lost, loss_q16;

	if (!tx->adaptive_valid) {
		tx->adaptive_valid = true;
		uwg_fec_adaptive_window_reset(tx, counter, now);
		return;
	}
	if (counter < tx->adaptive_base) {
		/* Small backward jumps are reordering, but a huge one means
		 * the counters restarted after a rekey.
		 */
		if (tx->adaptive_base - counter > 1U << 20)
			uwg_fec_adaptive_window_reset(tx, counter, now);
		return;
	}
	if (counter > tx->adaptive_largest)
		tx->adaptive_largest = counter;
	tx->adaptive_received++;
	expected = tx->adaptive_largest - tx->adaptive_base + 1;
	if (expected < UWG_FEC_ADAPTIVE_MIN_WINDOW)
		return;
	if (unlikely(expected > UWG_FEC_ADAPTIVE_MAX_WINDOW)) {
		/* A counter jump this large is a restart, not loss: drop the
		 * segment instead of turning it into a bogus estimate.
		 */
		tx->adaptive_base = tx->adaptive_largest + 1;
		tx->adaptive_received = 0;
		tx->adaptive_segment_start = now;
		return;
	}
	/* Do not close the window before it had time to settle. Reordered
	 * packets still arrive after the gap opened; as long as the window
	 * stays open they are counted in adaptive_received, while a real lost
	 * counter never arrives. This is what separates reordering from loss.
	 */
	if (time_before(now, tx->adaptive_segment_start +
				     UWG_FEC_ADAPTIVE_SETTLE_JIFFIES))
		return;
	lost = expected > tx->adaptive_received ?
		expected - tx->adaptive_received : 0;
	loss_q16 = (u32)div_u64(lost << 16, expected);
	if (!tx->adaptive_loss_q16)
		tx->adaptive_loss_q16 = loss_q16;
	else
		tx->adaptive_loss_q16 =
			(tx->adaptive_loss_q16 * 3 + loss_q16) / 4;
	tx->adaptive_observed += expected;
	tx->adaptive_base = tx->adaptive_largest + 1;
	tx->adaptive_received = 0;
	tx->adaptive_segment_start = now;
	if (!tx->adaptive_on) {
		if (tx->adaptive_observed >= 1024 &&
		    tx->adaptive_loss_q16 > 655) {
			tx->adaptive_on = true;
			/* Stale clean time from before the switch would make
			 * the first clean sample turn adaptive off again
			 * immediately.
			 */
			tx->adaptive_clean_since = 0;
		}
	} else if (tx->adaptive_loss_q16 < 131) {
		if (!tx->adaptive_clean_since)
			tx->adaptive_clean_since = now;
		else if (time_after(now, tx->adaptive_clean_since + 5 * HZ)) {
			tx->adaptive_on = false;
			tx->adaptive_clean_since = 0;
			tx->adaptive_observed = 0;
			tx->adaptive_loss_q16 = 0;
		}
	} else {
		tx->adaptive_clean_since = 0;
	}
}

void uwg_fec_adaptive_observe(struct uwg_peer *peer, u64 counter)
{
	struct uwg_fec_tx *tx;

	rcu_read_lock();
	tx = rcu_dereference(peer->fec_tx);
	if (!tx || !tx->adaptive)
		goto out;
	spin_lock_bh(&tx->lock);
	uwg_fec_adaptive_observe_locked(tx, counter, jiffies);
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
	unsigned int i, n = tx->count, shard_len = 0, total, limit;
	u8 block_k, block_m, order[UWG_FEC_DATA_MAX_SHARDS];
	u32 block_id;

	if (!n)
		return;
	/* Taken from the peer, not from this tx instance: replacing the FEC
	 * state on a profile change must not restart the sequence, or the
	 * receiver's block clock would drop every new id as stale.
	 */
	block_id = (u32)atomic_fetch_inc(&peer->fec_block_id);

	for (i = 0; i < n; i++) {
		unsigned int len = (unsigned int)tx->lens[i] + 2;

		if (len > shard_len)
			shard_len = len;
	}
	if (shard_len < 2 || shard_len > UWG_FEC_DATA_SHARD_CAP) {
		atomic64_inc(&peer->fec_counters.dropped_bounds);
		goto out;
	}

	/* Add a random tail to the whole block. All shards keep the same
	 * length for Reed-Solomon, but the length no longer pins down the
	 * largest inner packet, and it may stay below the MTU budget.
	 */
	limit = uwg_fec_tx_limit(peer);
	if (limit > shard_len) {
		unsigned int extra = get_random_u32_below(UWG_FEC_DATA_SHARD_SLACK);

		shard_len += min(extra, limit - shard_len);
	}

	/* Only the encoder needs a contiguous block; without parity the shards
	 * are copied straight from tx->shards into their skbs below.
	 */
	block_k = with_parity ? tx->k : (u8)n;
	block_m = with_parity ? tx->m : 0;
	if (with_parity) {
		for (i = 0; i < n; i++) {
			unsigned int copy = (unsigned int)tx->lens[i] + 2;
			u8 *dst = tx->block + (size_t)i * shard_len;

			memcpy(dst,
			       tx->shards + (size_t)i * UWG_FEC_DATA_SHARD_CAP,
			       copy);
			if (copy < shard_len)
				memset(dst + copy, 0, shard_len - copy);
		}
		if (uwg_fec_encode(tx->k, tx->m, shard_len, tx->block,
				   tx->block + (size_t)tx->k * shard_len)) {
			block_m = 0;
			block_k = (u8)n;
		}
	}
	total = (unsigned int)block_k + block_m;
	atomic64_inc(&peer->fec_counters.blocks_encoded);

	/* Shuffle the send order: indexes and the parity bit stay correct, but
	 * parity no longer always arrives last and the block is not a single
	 * constant-size burst.
	 */
	for (i = 0; i < total; i++)
		order[i] = (u8)i;
	for (i = total; i > 1; i--) {
		unsigned int j = get_random_u32_below(i);
		u8 tmp = order[i - 1];

		order[i - 1] = order[j];
		order[j] = tmp;
	}

	for (i = 0; i < total; i++) {
		struct uwg_ext_fec_shard shard;
		struct sk_buff *skb;
		unsigned int index = order[i];
		u8 *hdr;

		memset(&shard, 0, sizeof(shard));
		shard.block_id = block_id;
		shard.index = (u8)index;
		shard.k = block_k;
		shard.m = block_m;
		shard.flags = index >= block_k ? UWG_EXT_FEC_FLAG_PARITY : 0;
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
		if (index < block_k && index < n) {
			const u8 *src = tx->shards +
				(size_t)index * UWG_FEC_DATA_SHARD_CAP;
			unsigned int copy = (unsigned int)tx->lens[index] + 2;
			u8 *dst = skb_put(skb, shard_len);

			memcpy(dst, src, copy);
			if (copy < shard_len)
				memset(dst + copy, 0, shard_len - copy);
		} else {
			skb_put_data(skb,
				     tx->block + (size_t)index * shard_len,
				     shard_len);
		}
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
		atomic64_inc(&peer->fec_counters.shards_sent);
	}

out:
	tx->count = 0;
}

static bool uwg_fec_tx_push_locked(struct uwg_fec_tx *tx,
				   struct uwg_peer *peer, struct sk_buff *skb,
				   struct sk_buff_head *out)
{
	unsigned int plen = skb->len;
	unsigned int limit = uwg_fec_tx_limit(peer);
	u8 *slot;

	if (unlikely(tx->disabled)) {
		atomic64_inc(&peer->fec_counters.dropped_disabled);
		return false;
	}
	if (plen + 2 > limit) {
		atomic64_inc(&peer->fec_counters.dropped_bounds);
		return false;
	}
	if (tx->count >= tx->k)
		return false;
	slot = tx->shards + (size_t)tx->count * UWG_FEC_DATA_SHARD_CAP;
	if (unlikely(skb_copy_bits(skb, 0, slot + 2, plen))) {
		atomic64_inc(&peer->fec_counters.dropped_bounds);
		return false;
	}
	put_unaligned_le16((u16)plen, slot);
	tx->lens[tx->count] = (u16)plen;
	tx->count++;
	if (tx->count == 1)
		mod_timer(&tx->timer,
			  jiffies + max_t(unsigned long, 1,
					  usecs_to_jiffies(
						  get_random_u32_inclusive(
							UWG_FEC_DATA_TX_DELAY_MIN_US,
							UWG_FEC_DATA_TX_DELAY_MAX_US))));
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
	if (skb->len + 2 > uwg_fec_tx_limit(peer)) {
		atomic64_inc(&peer->fec_counters.dropped_bounds);
		return false;
	}
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

	if (skb_queue_empty(out))
		return;
	/* Recovered packets are data the inner stack sees, so they keep the
	 * data path alive even when every underlay packet was a shard. The
	 * plain shard path arms the timer in uwg_ext_handle_fec_shard(); this
	 * covers packets reconstructed here after their shard was lost.
	 */
	uwg_timers_data_received(peer);
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
	    shard->shard_len > UWG_FEC_DATA_SHARD_CAP) {
		atomic64_inc(&peer->fec_counters.dropped_bounds);
		return -EINVAL;
	}

	rcu_read_lock();
	rx = rcu_dereference(peer->fec_rx);
	if (unlikely(!rx)) {
		atomic64_inc(&peer->fec_counters.dropped_disabled);
		ret = -EINVAL;
		goto out_rcu;
	}
	/* A shard carries its own profile and is authenticated, so a shard that
	 * matches the local RX profile is decodable even when the peer's CAPS
	 * are not known yet. That happens after the peer was re-created: it
	 * forgot the profile we advertised and starts sending shards before the
	 * CAPS exchange completes. Rejecting them here turned a lost CAPS into
	 * a permanent one-way black hole. The profile checks below remain the
	 * real guard.
	 */
	if (unlikely(!READ_ONCE(peer->caps.peer_valid) ||
		     !(READ_ONCE(peer->caps.peer.flags) & UWG_EXT_CAP_FEC)))
		net_dbg_ratelimited("%s: FEC shard from peer %llu arrives before CAPS\n",
				    peer->device->dev->name,
				    peer->internal_id);
	if (shard->m == 0) {
		if (!shard->k || shard->k > rx->k)
			invalid = true;
	} else if (shard->k != rx->k || shard->m != rx->m) {
		invalid = true;
	}
	if (invalid) {
		atomic64_inc(&peer->fec_counters.dropped_bounds);
		ret = -EINVAL;
		goto out_rcu;
	}

	__skb_queue_head_init(&out);
	spin_lock_bh(&rx->lock);
	if (unlikely(rx->disabled)) {
		atomic64_inc(&peer->fec_counters.dropped_disabled);
		ret = -EINVAL;
		goto out_unlock;
	}
	if (!rx->keypair_valid || rx->keypair_id != keypair_id)
		uwg_fec_rx_reset_locked(rx, keypair_id);
	if (!rx->have_next) {
		rx->next_id = shard->block_id;
		rx->have_next = true;
	}
	if ((s32)(shard->block_id - rx->next_id) < 0) {
		atomic64_inc(&peer->fec_counters.dropped_bounds);
		goto out_unlock;
	}

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
		atomic64_inc(&peer->fec_counters.dropped_bounds);
		ret = -EINVAL;
		goto out_unlock;
	}

	if (!blk->have[shard->index]) {
		if (unlikely(skb_copy_bits(skb, offset,
					   uwg_fec_rx_slot(rx, slot,
							   shard->index),
					   shard->shard_len))) {
			atomic64_inc(&peer->fec_counters.dropped_bounds);
			ret = -EINVAL;
			goto out_unlock;
		}
		blk->have[shard->index] = true;
		blk->present++;
	}

	if (blk->m == 0) {
		if (!blk->ready && blk->present == blk->k) {
			blk->ready = true;
			atomic64_inc(&peer->fec_counters.blocks_decoded);
		}
	} else if (!blk->ready && blk->present >= blk->k) {
		u8 *shards[UWG_FEC_DATA_MAX_SHARDS];
		bool present[UWG_FEC_DATA_MAX_SHARDS];
		unsigned int total = blk->k + blk->m;

		for (i = 0; i < total; i++) {
			shards[i] = uwg_fec_rx_slot(rx, slot, i);
			present[i] = blk->have[i];
		}
		if (!uwg_fec_decode(blk->k, blk->m, blk->shard_len,
				    shards, present)) {
			unsigned int j, missing = 0;

			for (j = 0; j < blk->k; j++) {
				if (!blk->have[j])
					missing++;
			}
			blk->ready = true;
			atomic64_inc(&peer->fec_counters.blocks_decoded);
			atomic64_add(missing,
				     &peer->fec_counters.packets_recovered);
		} else {
			blk->used = false;
			atomic64_inc(&peer->fec_counters.decode_fail);
		}
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
	peer->caps.reply_attempts = 0;
	peer->caps.next_send = 0;
	peer->caps.last_sent = 0;
	WRITE_ONCE(peer->caps.resend, true);
	spin_unlock_bh(&peer->caps.lock);
}

static bool uwg_fec_state_matches(struct uwg_peer *peer, bool want,
				  u8 k, u8 m, bool adaptive)
{
	struct uwg_fec_tx *tx = rcu_dereference_protected(peer->fec_tx, 1);
	struct uwg_fec_rx *rx = rcu_dereference_protected(peer->fec_rx, 1);

	if (!want)
		return !tx && !rx;
	return tx && rx && tx->k == k && tx->m == m && rx->k == k &&
	       rx->m == m && tx->adaptive == adaptive && rx->adaptive == adaptive;
}

/* Stop a tx/rx pair that has already been unpublished and followed by a
 * synchronize_net(): in-flight readers may have armed its timers, so they
 * can only be shut down once those readers are gone.
 */
static void uwg_fec_state_stop(struct uwg_fec_tx *tx, struct uwg_fec_rx *rx)
{
	if (tx) {
		spin_lock_bh(&tx->lock);
		tx->disabled = true;
		spin_unlock_bh(&tx->lock);
		timer_shutdown_sync(&tx->timer);
		uwg_fec_tx_free(tx);
	}
	if (rx) {
		spin_lock_bh(&rx->lock);
		rx->disabled = true;
		spin_unlock_bh(&rx->lock);
		timer_shutdown_sync(&rx->timer);
		uwg_fec_rx_free(rx);
	}
}

struct uwg_fec_sync_entry {
	struct uwg_peer *peer;
	struct uwg_fec_tx *old_tx, *tx;
	struct uwg_fec_rx *old_rx, *rx;
	bool fresh;
};

/* Allocate the state for the requested profile without touching the live
 * one. On -ENOMEM the peer keeps running with its previous tx/rx pair, so it
 * still decodes exactly the profile CAPS advertised before the change.
 */
static int uwg_fec_state_prepare(struct uwg_peer *peer, bool want, u8 k,
				 u8 m, bool adaptive,
				 struct uwg_fec_sync_entry *entry)
{
	struct uwg_fec_tx *tx = rcu_dereference_protected(peer->fec_tx, 1);
	struct uwg_fec_rx *rx = rcu_dereference_protected(peer->fec_rx, 1);

	entry->peer = peer;
	entry->old_tx = tx;
	entry->old_rx = rx;
	entry->tx = tx;
	entry->rx = rx;
	entry->fresh = false;

	if (!want) {
		entry->tx = NULL;
		entry->rx = NULL;
		return 0;
	}
	if (uwg_fec_state_matches(peer, want, k, m, adaptive))
		return 0;

	tx = uwg_fec_tx_alloc(peer, k, m, adaptive);
	if (!tx)
		return -ENOMEM;
	rx = uwg_fec_rx_alloc(peer, k, m, adaptive);
	if (!rx) {
		uwg_fec_tx_free(tx);
		return -ENOMEM;
	}
	entry->tx = tx;
	entry->rx = rx;
	entry->fresh = true;
	return 0;
}

int uwg_peer_fec_sync(struct uwg_peer *peer)
{
	struct uwg_device *uwg = peer->device;
	struct uwg_fec_sync_entry entry;
	u8 k = 0, m = 0;
	bool adaptive = false;
	bool want;
	int ret;

	want = uwg_fec_mode_config(READ_ONCE(uwg->fec_mode), &k, &m,
				   &adaptive);
	ret = uwg_fec_state_prepare(peer, want, k, m, adaptive, &entry);
	if (ret)
		return ret;
	if (entry.old_tx == entry.tx && entry.old_rx == entry.rx)
		return 0;

	rcu_assign_pointer(peer->fec_tx, entry.tx);
	rcu_assign_pointer(peer->fec_rx, entry.rx);
	uwg_fec_mark_resend(peer);
	if (entry.old_tx || entry.old_rx) {
		synchronize_net();
		uwg_fec_state_stop(entry.old_tx, entry.old_rx);
	}
	uwg_ext_maybe_send_caps(peer);
	return 0;
}

static bool uwg_fec_device_synced(struct uwg_device *uwg, bool want,
				  u8 k, u8 m, bool adaptive)
{
	struct uwg_peer *peer;

	list_for_each_entry(peer, &uwg->peer_list, peer_list) {
		if (!uwg_fec_state_matches(peer, want, k, m, adaptive))
			return false;
	}
	return true;
}

int uwg_peer_fec_sync_device(struct uwg_device *uwg, u32 mode)
{
	struct uwg_fec_sync_entry *entries;
	struct uwg_peer *peer;
	unsigned int i, count = 0, n;
	u8 k = 0, m = 0;
	bool adaptive = false;
	bool want;
	int ret = 0;

	lockdep_assert_held(&uwg->device_update_lock);

	want = uwg_fec_mode_config(mode, &k, &m, &adaptive);
	if (!want && mode != UWG_FEC_MODE_OFF)
		return -EINVAL;
	if (uwg_fec_device_synced(uwg, want, k, m, adaptive)) {
		WRITE_ONCE(uwg->fec_mode, mode);
		return 0;
	}

	n = uwg->num_peers;
	if (!n)
		return 0;
	entries = kvcalloc(n, sizeof(*entries), GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	/* Prepare phase: allocate everything first. If any peer fails, the
	 * live state is untouched and the caller can safely keep the old
	 * fec_mode, so CAPS never promises a profile without a matching RX.
	 */
	list_for_each_entry(peer, &uwg->peer_list, peer_list) {
		if (WARN_ON_ONCE(count >= n)) {
			ret = -EINVAL;
			goto err_discard;
		}
		ret = uwg_fec_state_prepare(peer, want, k, m, adaptive,
					    &entries[count]);
		if (ret)
			goto err_discard;
		++count;
	}

	/* Commit phase: publish every prepared state, then wait out the old
	 * readers once. Nothing can fail from here on.
	 */
	for (i = 0; i < count; ++i) {
		struct uwg_fec_sync_entry *entry = &entries[i];

		if (entry->old_tx == entry->tx && entry->old_rx == entry->rx)
			continue;
		rcu_assign_pointer(entry->peer->fec_tx, entry->tx);
		rcu_assign_pointer(entry->peer->fec_rx, entry->rx);
		uwg_fec_mark_resend(entry->peer);
	}
	/* Commit point: the new RX state is in place before CAPS starts
	 * advertising it, so a peer can never send a profile we cannot decode.
	 */
	WRITE_ONCE(uwg->fec_mode, mode);
	synchronize_net();
	for (i = 0; i < count; ++i) {
		struct uwg_fec_sync_entry *entry = &entries[i];

		if (entry->old_tx == entry->tx && entry->old_rx == entry->rx)
			continue;
		uwg_fec_state_stop(entry->old_tx, entry->old_rx);
	}
	/* The caller advertises the committed profile: uwg_ext_caps_changed()
	 * re-arms one CAPS burst per peer once fec_mode is visible. Sending here
	 * as well would put two identical CAPS frames on the wire for a single
	 * change and burn the retry budget twice. The committed per-peer state
	 * must match what CAPS advertises.
	 */
	WARN_ON_ONCE(!uwg_fec_device_synced(uwg, want, k, m, adaptive));
	kvfree(entries);
	return 0;

err_discard:
	for (i = 0; i < count; ++i) {
		if (!entries[i].fresh)
			continue;
		uwg_fec_tx_free(entries[i].tx);
		uwg_fec_rx_free(entries[i].rx);
	}
	kvfree(entries);
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
	uwg_fec_state_stop(tx, rx);
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

void uwg_fec_stats_fill(const struct uwg_peer *peer,
			struct uwg_fec_stats *stats)
{
	stats->blocks_encoded =
		atomic64_read(&peer->fec_counters.blocks_encoded);
	stats->shards_sent = atomic64_read(&peer->fec_counters.shards_sent);
	stats->blocks_decoded =
		atomic64_read(&peer->fec_counters.blocks_decoded);
	stats->packets_recovered =
		atomic64_read(&peer->fec_counters.packets_recovered);
	stats->decode_fail = atomic64_read(&peer->fec_counters.decode_fail);
	stats->dropped_bounds =
		atomic64_read(&peer->fec_counters.dropped_bounds);
	stats->dropped_disabled =
		atomic64_read(&peer->fec_counters.dropped_disabled);
}

/* Caller must hold device_update_lock, which keeps peer_list stable; the
 * netlink device dump is the intended caller.
 */
void uwg_fec_stats_fill_device(struct uwg_device *uwg,
			       struct uwg_fec_stats *stats)
{
	struct uwg_fec_stats peer_stats;
	struct uwg_peer *peer;

	lockdep_assert_held(&uwg->device_update_lock);
	memset(stats, 0, sizeof(*stats));
	list_for_each_entry(peer, &uwg->peer_list, peer_list) {
		uwg_fec_stats_fill(peer, &peer_stats);
		stats->blocks_encoded += peer_stats.blocks_encoded;
		stats->shards_sent += peer_stats.shards_sent;
		stats->blocks_decoded += peer_stats.blocks_decoded;
		stats->packets_recovered += peer_stats.packets_recovered;
		stats->decode_fail += peer_stats.decode_fail;
		stats->dropped_bounds += peer_stats.dropped_bounds;
		stats->dropped_disabled += peer_stats.dropped_disabled;
	}
}

/* Deterministic check of the reorder-vs-loss decision. It feeds the same
 * counter sequence the data plane would see, but with a controlled clock: a
 * clean link whose every fourth counter is delayed to the end of the segment
 * must not look lossy, while a link that really drops 2% must arm. The second
 * half also guards the adaptive clean-timer reset on (re)enable.
 */
static bool uwg_fec_adaptive_selftest(void)
{
	struct uwg_fec_tx tx;
	unsigned long now = jiffies;
	u64 i;
	bool ok = true;

#define A_CHECK(cond) do {						\
		if (!(cond)) {						\
			pr_err("FEC adaptive self-test: FAIL (%s)\n",	\
			       #cond);					\
			ok = false;					\
		}							\
	} while (0)

	memset(&tx, 0, sizeof(tx));
	tx.adaptive = true;

	/* Clean link, every fourth counter arrives only at the end. */
	uwg_fec_adaptive_observe_locked(&tx, 0, now);
	for (i = 1; i <= 4096; i++)
		if (i % 4)
			uwg_fec_adaptive_observe_locked(&tx, i, now);
	for (i = 4; i <= 4096; i += 4)
		uwg_fec_adaptive_observe_locked(&tx, i, now);
	now += HZ;
	uwg_fec_adaptive_observe_locked(&tx, 4097, now);
	A_CHECK(!tx.adaptive_on);
	A_CHECK(!tx.adaptive_loss_q16);

	/* Same window with a real 2% loss: every 50th counter never arrives. */
	memset(&tx, 0, sizeof(tx));
	tx.adaptive = true;
	uwg_fec_adaptive_observe_locked(&tx, 0, now);
	/* Simulate a stale clean timestamp left over from the disabled
	 * period: enabling must discard it, or the next clean sample turns
	 * adaptive off immediately.
	 */
	tx.adaptive_clean_since = now - 10 * HZ;
	for (i = 1; i <= 4096; i++)
		if (i % 50)
			uwg_fec_adaptive_observe_locked(&tx, i, now);
	now += HZ;
	uwg_fec_adaptive_observe_locked(&tx, 4097, now);
	A_CHECK(tx.adaptive_on);
	A_CHECK(!tx.adaptive_clean_since);

	/* One clean sample right after enabling must not switch it off. */
	now += HZ;
	for (i = 4098; i < 4098 + UWG_FEC_ADAPTIVE_MIN_WINDOW; i++)
		uwg_fec_adaptive_observe_locked(&tx, i, now);
	A_CHECK(tx.adaptive_on);

	/* ... but a run of clean samples does. The EWMA starts at the lossy
	 * estimate, so it takes several one-second segments to decay and
	 * then five more to expire the clean timer.
	 */
	{
		u64 counter = 4098 + UWG_FEC_ADAPTIVE_MIN_WINDOW;
		unsigned int sec;

		for (sec = 0; sec < 20; sec++) {
			now += HZ;
			for (i = 0; i < UWG_FEC_ADAPTIVE_MIN_WINDOW;
			     i++, counter++)
				uwg_fec_adaptive_observe_locked(&tx, counter,
								now);
		}
	}
	A_CHECK(!tx.adaptive_on);

#undef A_CHECK
	return ok;
}

int uwg_fec_mtu_selftest(void)
{
	static const unsigned int underlays[] = { 576, 1280, 1500, 9000 };
	unsigned int i, test_num = 0;
	bool ok = true;

#define T_CHECK(cond) do {						\
		++test_num;						\
		if (!(cond)) {						\
			pr_err("FEC MTU self-test %u: FAIL (%s)\n",	\
			       test_num, #cond);			\
			ok = false;					\
		}							\
	} while (0)

	/* The wire overhead has to cover the exact builder in
	 * uwg_fec_tx_emit(): two length bytes, both extension headers, the
	 * message header and auth tag, the 16 byte alignment and the random
	 * tail, and the outer IP/UDP headers.
	 */
	T_CHECK(MESSAGE_MINIMUM_LENGTH ==
		sizeof(struct message_data) + NOISE_AUTHTAG_LEN);
	T_CHECK(UWG_UNDERLAY_MTU_MAX == 65535);
	T_CHECK(UWG_FEC_SHARD_WIRE_OVERHEAD ==
		UWG_FEC_UNDERLAY_IP_UDP_OVERHEAD + MESSAGE_MINIMUM_LENGTH +
		UWG_EXT_HEADER_LEN + UWG_EXT_FEC_HEADER_LEN + 2 +
		MESSAGE_PADDING_MULTIPLE - 1 + MESSAGE_PADDING_MULTIPLE - 1);
	T_CHECK(UWG_FEC_SHARD_WIRE_OVERHEAD == 132);

	for (i = 0; i < ARRAY_SIZE(underlays); i++) {
		unsigned int underlay = underlays[i];
		unsigned int allowed = uwg_fec_allowed_inner(underlay);
		unsigned int shard_len = allowed + 2;
		unsigned int datagram;

		T_CHECK(allowed == underlay - UWG_FEC_SHARD_WIRE_OVERHEAD);
		/* Worst case shard: full-size inner packet, every padding
		 * byte present, largest headers.
		 */
		datagram = UWG_FEC_UNDERLAY_IP_UDP_OVERHEAD +
			   MESSAGE_MINIMUM_LENGTH + UWG_EXT_HEADER_LEN +
			   UWG_EXT_FEC_HEADER_LEN + shard_len +
			   UWG_FEC_SHARD_PADDING_MAX;
		T_CHECK(datagram == underlay);
	}

	/* 1500 keeps the shard budget the old formula produced for the
	 * default 1420 MTU (1420 + 2 - 52), but now the TUN MTU itself is
	 * lowered to that value, so no packet escapes to the legacy path.
	 */
	T_CHECK(uwg_fec_target_mtu(1500, 1420, true) == 1368);
	T_CHECK(uwg_fec_allowed_inner(1500) + 2 == 1370);
	/* A 9000 byte underlay must not raise the MTU above the base one. */
	T_CHECK(uwg_fec_target_mtu(9000, 1420, true) == 1420);
	/* ... but a base MTU above the shard cap is clamped to the cap. */
	T_CHECK(uwg_fec_target_mtu(9000, 9000, true) ==
		UWG_FEC_DATA_SHARD_CAP - 2);
	T_CHECK(uwg_fec_target_mtu(1280, 1420, true) == 1148);
	T_CHECK(uwg_fec_target_mtu(1280, 1420, true) >= UWG_UNDERLAY_MTU_MIN);
	/* Below the IPv4 minimum the MTU is clamped, and the excess packets
	 * fall back to the legacy path through uwg_fec_tx_push().
	 */
	T_CHECK(uwg_fec_target_mtu(576, 1420, true) == UWG_UNDERLAY_MTU_MIN);
	T_CHECK(uwg_fec_target_mtu(576, 1420, true) > uwg_fec_allowed_inner(576));
	/* With FEC off the base MTU is returned untouched, whatever the
	 * underlay says.
	 */
	T_CHECK(uwg_fec_target_mtu(1500, 1420, false) == 1420);
	T_CHECK(uwg_fec_target_mtu(576, 1420, false) == 1420);
	T_CHECK(uwg_fec_adaptive_selftest());

	if (!ok)
		return -EINVAL;
	pr_info("FEC MTU self-test: 1..%u passed\n", test_num);
	return 0;
#undef T_CHECK
}
