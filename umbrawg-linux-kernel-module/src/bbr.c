// SPDX-License-Identifier: GPL-2.0
/*
 * BBRv3-style congestion controller for UmbraWG.
 *
 * Ported from the Rust crate umbrawg-cc. The controller only consumes the
 * outer-flow ACK stream (largest counter + 64-bit bitmap) and produces a
 * pacing rate and a congestion window. It carries no data path state, uses
 * no floating point and never sleeps.
 *
 * Deviations from the Rust crate, all intentional:
 *   - DRAIN is skipped for tunnels: as soon as STARTUP declares the pipe
 *     full the controller switches to PROBE_BW at gain 1.0, so the sender
 *     is never parked waiting for an application queue to drain.
 *   - ECN is not wired: the ACK API carries no ECN-CE flag.
 *   - There is no timer callback. Time-based work (PROBE_RTT exit, phase
 *     watchdog) runs on ACK/LOSS events, and stale records are bounded by
 *     the ring capacity instead of a periodic sweep.
 *   - Loss is inferred from ACK bitmap holes and from records leaving the
 *     64-bit window without an ACK. Loss cuts are deferred until STARTUP
 *     ends, so random loss cannot abort bandwidth discovery.
 *   - cwnd is not translated into a sleep. It is enforced by the sender as
 *     an ACK-clocked gate on the staged queue (see uwg_packet_cwnd_gate()
 *     in send.c); the pacer below applies only the token bucket.
 *   - The send ring holds 4096 records of 24 bytes (96 KiB) instead of the
 *     8192 records of 32 bytes (256 KiB) the Rust crate uses; see bbr.h.
 */

#include <linux/bitops.h>
#include <linux/build_bug.h>
#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time64.h>

#include "bbr.h"

#define UWG_BBR_NSEC_PER_SEC 1000000000ULL
#define UWG_BBR_GAIN_UNIT 1000ULL
#define UWG_BBR_STARTUP_GAIN 2770ULL
#define UWG_BBR_CWND_GAIN 2000ULL
#define UWG_BBR_MAX_RATE (1ULL << 50)
#define UWG_BBR_MAX_CWND (1ULL << 34)
#define UWG_BBR_MIN_RTT_SAMPLE_NS 1000ULL
#define UWG_BBR_MIN_RTT_WINDOW_NS (10ULL * UWG_BBR_NSEC_PER_SEC)
#define UWG_BBR_PROBE_RTT_DURATION_NS 200000000ULL
#define UWG_BBR_FULL_BW_THRESHOLD 1250ULL
#define UWG_BBR_FULL_BW_ROUNDS 3U
#define UWG_BBR_LOSS_THRESHOLD_PCT 20ULL
#define UWG_BBR_LOSS_COMPENSATION_MAX_PCT 25ULL
#define UWG_BBR_HI_GROWTH_DIVISOR 64ULL
/*
 * The pacing rate must stay close to cwnd/RTT: a large multiplier makes the
 * window decorative. 1.25 leaves room for delayed ACKs and loss compensation
 * without letting the sender ignore the congestion window.
 */
#define UWG_BBR_RATE_SANITY_GAIN 4000ULL
#define UWG_BBR_RATE_SANITY_UNIT 1000ULL
#define UWG_BBR_ACK_WINDOW 63ULL
#define UWG_BBR_MAX_DATAGRAM 65535U
#define UWG_BBR_BW_WINDOW_ROUNDS 10U

#define UWG_BBR_RING_MASK (UWG_BBR_RING_CAPACITY - 1)
#define UWG_BBR_STATE_SHIFT 29
#define UWG_BBR_DELIVERED_MASK ((1ULL << UWG_BBR_STATE_SHIFT) - 1)

static_assert((UWG_BBR_RING_CAPACITY & (UWG_BBR_RING_CAPACITY - 1)) == 0,
	      "BBR ring capacity must be a power of two");

static const u64 uwg_bbr_cycle_gains[8] = {
	1250, 750, 1000, 1000, 1000, 1000, 1000, 1000,
};

static inline u64 uwg_ns_sub(u64 a, u64 b)
{
	return a > b ? a - b : 0;
}

static inline u64 uwg_sat_add(u64 a, u64 b)
{
	u64 res;

	return check_add_overflow(a, b, &res) ? U64_MAX : res;
}

static inline u64 uwg_sat_mul(u64 a, u64 b)
{
	u64 res;

	return check_mul_overflow(a, b, &res) ? U64_MAX : res;
}

/*
 * (a * b) / d with saturation. On overflow the 128-bit product is larger
 * than U64_MAX, so the true quotient exceeds U64_MAX / d; returning that
 * lower bound is safe for every caller (all of them clamp the result).
 */
static inline u64 uwg_mul_div(u64 a, u64 b, u64 d)
{
	u64 prod;

	if (!d)
		return U64_MAX;
	if (!a || !b)
		return 0;
	if (check_mul_overflow(a, b, &prod))
		return U64_MAX / d;
	return div64_u64(prod, d);
}

static inline u64 uwg_max3(u64 a, u64 b, u64 c)
{
	return max3(a, b, c);
}

static inline u8 uwg_slot_state(const struct uwg_bbr_sent *slot)
{
	return (u8)(slot->delivered_state >> UWG_BBR_STATE_SHIFT);
}

/* True while the record's bytes are still counted in b->inflight. */
static inline bool uwg_slot_inflight(const struct uwg_bbr_sent *slot)
{
	u8 state = uwg_slot_state(slot);

	return state == UWG_BBR_SLOT_INFLIGHT ||
	       state == UWG_BBR_SLOT_LOST_NOTED;
}

static inline void uwg_slot_set_state(struct uwg_bbr_sent *slot, u8 state)
{
	slot->delivered_state = (slot->delivered_state & (u32)UWG_BBR_DELIVERED_MASK) |
				((u32)state << UWG_BBR_STATE_SHIFT);
}

/* Bytes delivered since the datagram was sent, modulo 2^29. */
static inline u64 uwg_delivered_since(const struct uwg_bbr *b,
				      const struct uwg_bbr_sent *slot)
{
	u32 now = (u32)(b->delivered & UWG_BBR_DELIVERED_MASK);
	u32 then = slot->delivered_state & (u32)UWG_BBR_DELIVERED_MASK;

	return (u64)((now - then) & (u32)UWG_BBR_DELIVERED_MASK);
}

static inline u64 uwg_delay_ns(u32 ack_delay_us)
{
	return (u64)ack_delay_us * 1000ULL;
}

/* Removes a peer-reported ACK delay from an interval, leaving 1 ns. */
static u64 uwg_subtract_delay(u64 interval_ns, u64 delay_ns)
{
	u64 delay;

	if (!interval_ns)
		return 1;
	delay = min(delay_ns, interval_ns - 1);
	return interval_ns - delay;
}

/*
 * RTT sample with the ACK delay removed. The delay is capped at half of
 * the raw sample so a hostile peer cannot drive the floor to zero.
 */
static u64 uwg_rtt_sample(u64 raw_ns, u64 ack_delay_ns)
{
	u64 delay;

	if (!raw_ns)
		return UWG_BBR_MIN_RTT_SAMPLE_NS;
	delay = min(ack_delay_ns, raw_ns / 2);
	return max(raw_ns - delay, UWG_BBR_MIN_RTT_SAMPLE_NS);
}

/*
 * Scales a delivery-rate sample up by the long-term loss ratio. The ACK
 * stream only counts delivered bytes, so on a stable-loss path the raw
 * rate is low by exactly that fraction. Capped at 25 % of loss.
 */
static u64 uwg_compensate_loss(u64 rate, u64 delivered, u64 lost)
{
	u64 total = uwg_sat_add(delivered, lost);
	u64 pct;

	if (!total || !lost)
		return rate;
	pct = uwg_sat_mul(lost, 100) / total;
	if (!pct || pct > UWG_BBR_LOSS_COMPENSATION_MAX_PCT)
		return rate;
	return uwg_mul_div(rate, 100, 100 - pct);
}

static void uwg_pacer_refill(struct uwg_bbr *b, u64 now_ns)
{
	struct uwg_bbr_pacer *p = &b->pacer;
	u64 elapsed;
	u64 whole;

	if (!p->started) {
		p->started = true;
		p->last_ns = now_ns;
		return;
	}
	elapsed = uwg_ns_sub(now_ns, p->last_ns);
	if (!elapsed)
		return;
	p->last_ns = now_ns;

	if (p->rate && elapsed > (U64_MAX - p->remainder) / p->rate) {
		whole = p->burst;
		p->remainder = 0;
	} else {
		u64 credit = p->rate * elapsed + p->remainder;

		whole = div64_u64(credit, UWG_BBR_NSEC_PER_SEC);
		p->remainder = credit - whole * UWG_BBR_NSEC_PER_SEC;
	}

	p->allowance += (s64)min(whole, p->burst);
	if (p->allowance > (s64)p->burst)
		p->allowance = (s64)p->burst;
}

/*
 * Same credit computation as uwg_pacer_refill(), without touching the
 * bucket. Used to answer "how long until len bytes fit?" without changing
 * the state the sender will see on the next on_send/on_ack.
 */
static s64 uwg_pacer_projected_allowance(const struct uwg_bbr_pacer *p,
					 u64 now_ns)
{
	s64 allowance = p->allowance;
	u64 elapsed;
	u64 whole;

	if (!p->started)
		return allowance;
	elapsed = uwg_ns_sub(now_ns, p->last_ns);
	if (!elapsed)
		return allowance;

	if (p->rate && elapsed > (U64_MAX - p->remainder) / p->rate) {
		whole = p->burst;
	} else {
		u64 credit = p->rate * elapsed + p->remainder;

		whole = div64_u64(credit, UWG_BBR_NSEC_PER_SEC);
	}

	allowance += (s64)min(whole, p->burst);
	if (allowance > (s64)p->burst)
		allowance = (s64)p->burst;
	return allowance;
}

static u64 uwg_pacer_burst(u64 rate, u64 mss)
{
	u64 by_time = div64_u64(rate, 1000);

	return max(max(by_time, uwg_sat_mul(mss, 2)), 1);
}

static void uwg_pacer_set_rate(struct uwg_bbr *b, u64 rate)
{
	struct uwg_bbr_pacer *p = &b->pacer;

	p->rate = min(max(rate, 1ULL), UWG_BBR_MAX_RATE);
	p->burst = uwg_pacer_burst(p->rate, p->mss);
	if (p->allowance > (s64)p->burst)
		p->allowance = (s64)p->burst;
}

static void uwg_pacer_consume(struct uwg_bbr *b, u64 len)
{
	struct uwg_bbr_pacer *p = &b->pacer;

	p->allowance -= (s64)len;
	if (p->allowance < -(s64)p->burst)
		p->allowance = -(s64)p->burst;
}

static void uwg_bw_add(struct uwg_bbr *b, u64 rate)
{
	u64 *slot = &b->bw.slots[b->bw.index];

	if (rate > *slot)
		*slot = rate;
}

static void uwg_bw_round_start(struct uwg_bbr *b, bool rotate)
{
	if (!rotate)
		return;
	b->bw.index = (b->bw.index + 1) % UWG_BBR_BW_WINDOW_ROUNDS;
	b->bw.slots[b->bw.index] = 0;
}

static u64 uwg_bw_max(const struct uwg_bbr *b)
{
	u64 best = 0;
	unsigned int i;

	for (i = 0; i < UWG_BBR_BW_WINDOW_ROUNDS; i++)
		best = max(best, b->bw.slots[i]);
	return best;
}

static void uwg_min_rtt_sample(struct uwg_bbr *b, u64 rtt_ns, u64 now_ns)
{
	if (!rtt_ns)
		return;
	b->min_rtt.latest_ns = rtt_ns;
	b->min_rtt.seen_latest = true;
	if (!b->min_rtt.seen_min || rtt_ns < b->min_rtt.min_ns) {
		b->min_rtt.min_ns = rtt_ns;
		b->min_rtt.stamp_ns = now_ns;
		b->min_rtt.seen_min = true;
	}
}

static inline u64 uwg_min_rtt_value(const struct uwg_bbr *b)
{
	return b->min_rtt.seen_min ? b->min_rtt.min_ns : b->initial_rtt_ns;
}

static void uwg_min_rtt_refresh(struct uwg_bbr *b, u64 now_ns)
{
	if (b->min_rtt.seen_latest) {
		b->min_rtt.min_ns = b->min_rtt.latest_ns;
		b->min_rtt.seen_min = true;
	}
	b->min_rtt.stamp_ns = now_ns;
}

/*
 * Advances the oldest-in-flight watermark past records that are no longer
 * accounted as in flight. Every counter is visited once over its lifetime,
 * so the cost is amortised O(1) per datagram; the budget only bounds the
 * worst case of a large counter gap (dropped/handshake-only nonces).
 */
static void uwg_ring_advance_oldest(struct uwg_bbr *b)
{
	unsigned int budget = UWG_BBR_RING_CAPACITY;

	if (!b->oldest_valid)
		return;

	while (budget-- && b->oldest_inflight <= b->max_sent) {
		struct uwg_bbr_sent *slot =
			&b->ring[b->oldest_inflight & UWG_BBR_RING_MASK];

		if (slot->counter == b->oldest_inflight &&
		    uwg_slot_inflight(slot))
			return;
		b->oldest_inflight++;
	}

	if (b->oldest_inflight > b->max_sent)
		b->oldest_valid = false;
}

/*
 * Inserts a record, returning the length of a displaced in-flight record
 * (0 when the displaced slot was not in flight).
 */
static u32 uwg_ring_insert(struct uwg_bbr *b, u64 counter, u32 len, u64 now_ns)
{
	struct uwg_bbr_sent *slot = &b->ring[counter & UWG_BBR_RING_MASK];
	u32 evicted = 0;

	if (uwg_slot_inflight(slot))
		evicted = slot->len;

	slot->counter = counter;
	slot->sent_ns = now_ns;
	slot->len = len;
	slot->delivered_state = (u32)(b->delivered & UWG_BBR_DELIVERED_MASK) |
				((u32)UWG_BBR_SLOT_INFLIGHT << UWG_BBR_STATE_SHIFT);
	return evicted;
}

/*
 * Returns 0 when the record is unknown, 1 when it was in flight and 2 when
 * it had been counted as a loss of this round (LOST_NOTED) and recovered.
 * In both successful cases the record is copied to @out.
 */
static int uwg_ring_mark_acked(struct uwg_bbr *b, u64 counter,
			       struct uwg_bbr_sent *out)
{
	struct uwg_bbr_sent *slot = &b->ring[counter & UWG_BBR_RING_MASK];
	u8 state = uwg_slot_state(slot);

	if (slot->counter != counter)
		return 0;
	if (state == UWG_BBR_SLOT_INFLIGHT) {
		*out = *slot;
		uwg_slot_set_state(slot, UWG_BBR_SLOT_ACKED);
		return 1;
	}
	if (state == UWG_BBR_SLOT_LOST_NOTED) {
		*out = *slot;
		uwg_slot_set_state(slot, UWG_BBR_SLOT_ACKED);
		return 2;
	}
	return 0;
}

/*
 * Returns 0 when the record is unknown, 1 when it was in flight, 2 when it
 * had already been counted as a loss of this round (LOST_NOTED), 3 when it
 * was dropped locally and 4 when the loss was already accounted (LOST).
 */
static int uwg_ring_mark_lost(struct uwg_bbr *b, u64 counter, u32 *len)
{
	struct uwg_bbr_sent *slot = &b->ring[counter & UWG_BBR_RING_MASK];
	u8 state = uwg_slot_state(slot);

	if (slot->counter != counter)
		return 0;
	if (state == UWG_BBR_SLOT_DROPPED)
		return 3;
	if (state == UWG_BBR_SLOT_LOST)
		return 4;
	if (state != UWG_BBR_SLOT_INFLIGHT && state != UWG_BBR_SLOT_LOST_NOTED)
		return 0;
	*len = slot->len;
	uwg_slot_set_state(slot, UWG_BBR_SLOT_LOST);
	return state == UWG_BBR_SLOT_INFLIGHT ? 1 : 2;
}

static void uwg_bbr_note_loss(struct uwg_bbr *b, u64 len, u64 now_ns);

/*
 * Releases records that the 64-bit ACK bitmap can no longer cover. They
 * left the window without being acknowledged, which is exactly the loss
 * signal the controller needs; the walk starts at the watermark instead of
 * scanning the whole ring.
 */
static void uwg_ring_release_unreachable(struct uwg_bbr *b, u64 largest,
					 u64 now_ns)
{
	unsigned int budget = UWG_BBR_RING_CAPACITY;

	if (!b->oldest_valid)
		return;

	while (budget-- && largest > b->oldest_inflight &&
	       largest - b->oldest_inflight > UWG_BBR_ACK_WINDOW) {
		u64 counter = b->oldest_inflight;
		struct uwg_bbr_sent *slot =
			&b->ring[counter & UWG_BBR_RING_MASK];
		u8 state = uwg_slot_state(slot);

		if (slot->counter == counter) {
			if (state == UWG_BBR_SLOT_INFLIGHT) {
				u32 len = slot->len;

				b->inflight = b->inflight > len ?
					      b->inflight - len : 0;
				uwg_slot_set_state(slot, UWG_BBR_SLOT_LOST);
				uwg_bbr_note_loss(b, len, now_ns);
			} else if (state == UWG_BBR_SLOT_LOST_NOTED) {
				u32 len = slot->len;

				b->inflight = b->inflight > len ?
					      b->inflight - len : 0;
				uwg_slot_set_state(slot, UWG_BBR_SLOT_LOST);
			}
		}
		b->oldest_inflight++;
	}

	uwg_ring_advance_oldest(b);
}

/*
 * Counts bitmap holes inside the ACK window as losses of the current round.
 * Only records that are still in flight qualify: ACKED, LOST and locally
 * DROPPED slots are skipped, and LOST_NOTED prevents double counting when
 * the explicit loss report arrives later. Bit 0 (the largest counter) is
 * always set by a well-formed ACK and is left to the normal ACK path.
 */
static void uwg_ring_note_holes(struct uwg_bbr *b, u64 largest, u64 bitmap,
				u64 now_ns)
{
	unsigned int bit;

	for (bit = 1; bit < 64 && (u64)bit <= largest; bit++) {
		struct uwg_bbr_sent *slot;
		u64 counter;

		if (bitmap & (1ULL << bit))
			continue;
		counter = largest - bit;
		slot = &b->ring[counter & UWG_BBR_RING_MASK];
		if (slot->counter != counter ||
		    uwg_slot_state(slot) != UWG_BBR_SLOT_INFLIGHT)
			continue;
		uwg_slot_set_state(slot, UWG_BBR_SLOT_LOST_NOTED);
		uwg_bbr_note_loss(b, slot->len, now_ns);
	}
}

static u64 uwg_bbr_bdp(const struct uwg_bbr *b)
{
	u64 rtt = uwg_min_rtt_value(b);
	u64 bdp = uwg_mul_div(b->btl_bw, rtt, UWG_BBR_NSEC_PER_SEC);

	return min(bdp, UWG_BBR_MAX_CWND);
}

static u64 uwg_bbr_phase_ns(const struct uwg_bbr *b)
{
	return uwg_min_rtt_value(b);
}

static u64 uwg_bbr_pacing_gain(const struct uwg_bbr *b)
{
	switch (b->mode) {
	case UWG_BBR_STARTUP:
		return UWG_BBR_STARTUP_GAIN;
	case UWG_BBR_PROBE_BW:
		return uwg_bbr_cycle_gains[b->cycle_idx % ARRAY_SIZE(uwg_bbr_cycle_gains)];
	case UWG_BBR_PROBE_RTT:
	default:
		return UWG_BBR_GAIN_UNIT;
	}
}

static void uwg_bbr_update_pacing(struct uwg_bbr *b, u64 now_ns)
{
	u64 gain = uwg_bbr_pacing_gain(b);
	u64 rate;

	if (!b->btl_bw)
		rate = b->initial_rate;
	else
		rate = uwg_mul_div(b->btl_bw, gain, UWG_BBR_GAIN_UNIT);
	rate = min(max(rate, 1ULL), UWG_BBR_MAX_RATE);
	b->pacing_rate = rate;
	uwg_pacer_set_rate(b, rate);
	uwg_pacer_refill(b, now_ns);
}

/* Applies the upper bounds that DRAIN would otherwise install. */
static void uwg_bbr_settle_bounds(struct uwg_bbr *b)
{
	u64 floor = max(uwg_bbr_bdp(b), b->min_cwnd);
	u64 ceiling = uwg_max3(b->inflight, b->cwnd, floor);

	/* Never raise a bound that a loss cut has already lowered. */
	b->inflight_hi = max(min(b->inflight_hi, ceiling), b->min_cwnd);
	if (b->inflight_lo > b->inflight_hi)
		b->inflight_lo = b->inflight_hi;
	b->bw_hi = b->btl_bw;
}

/* STARTUP is complete: go straight to PROBE_BW at a neutral gain. */
static void uwg_bbr_finish_startup(struct uwg_bbr *b, u64 now_ns)
{
	b->full_bw_reached = true;
	uwg_bbr_settle_bounds(b);
	b->mode = UWG_BBR_PROBE_BW;
	b->cycle_idx = 2;
	b->cycle_start_ns = now_ns;
}

static void uwg_bbr_cut_upper_bounds(struct uwg_bbr *b)
{
	u64 total = max(uwg_sat_add(b->round_delivered, b->round_lost), 1ULL);
	u64 pct = uwg_mul_div(b->round_lost, 100, total);
	u64 beta;
	u64 floor = max(uwg_bbr_bdp(b), b->min_cwnd);
	u64 base = max(b->round_max_inflight, b->inflight);
	u64 cut;

	pct = min(max(pct, UWG_BBR_LOSS_THRESHOLD_PCT), 50ULL);
	beta = UWG_BBR_GAIN_UNIT - pct * 10;
	cut = uwg_mul_div(base, beta, UWG_BBR_GAIN_UNIT);

	b->inflight_hi = max(min(b->inflight_hi, max(cut, floor)), b->min_cwnd);
	b->inflight_lo = max(min(min(b->inflight_lo, b->inflight_hi), cut), b->min_cwnd);
	b->last_cut_round = b->round_count;
}

static void uwg_bbr_apply_loss_cut(struct uwg_bbr *b, u64 now_ns)
{
	/*
	 * During STARTUP inflight_hi is not established yet: cutting it here
	 * would cap the window at the current (small) BtlBw estimate and the
	 * controller could never discover the real pipe. STARTUP exits on the
	 * BtlBw plateau instead.
	 */
	if (b->mode == UWG_BBR_STARTUP)
		return;

	uwg_bbr_cut_upper_bounds(b);
	if (b->mode == UWG_BBR_PROBE_BW &&
	    uwg_bbr_cycle_gains[b->cycle_idx % ARRAY_SIZE(uwg_bbr_cycle_gains)] >
		    UWG_BBR_GAIN_UNIT) {
		b->cycle_idx = 1;
		b->cycle_start_ns = now_ns;
	}
}

static void uwg_bbr_adapt_bounds(struct uwg_bbr *b)
{
	u64 bdp;
	u64 floor;
	u64 total;
	u64 lossy;
	bool congestion;

	if (b->mode == UWG_BBR_PROBE_RTT)
		return;

	bdp = uwg_bbr_bdp(b);
	floor = max(bdp, b->min_cwnd);
	total = uwg_sat_add(b->round_delivered, b->round_lost);
	lossy = total &&
		uwg_sat_mul(b->round_lost, 100) >= uwg_sat_mul(total, UWG_BBR_LOSS_THRESHOLD_PCT);
	congestion = lossy || b->round_congestion;

	if (congestion && b->mode != UWG_BBR_STARTUP) {
		if (b->round_max_inflight && b->last_cut_round != b->round_count)
			uwg_bbr_cut_upper_bounds(b);
	} else if (b->mode != UWG_BBR_STARTUP) {
		if (uwg_sat_mul(b->btl_bw, 100) >
		    max(uwg_sat_mul(b->bw_hi, 105), 1ULL)) {
			b->inflight_hi = max(b->inflight_hi,
					     max(uwg_sat_mul(bdp, 2), b->min_cwnd));
			b->bw_hi = b->btl_bw;
		}
		if (uwg_sat_mul(b->round_max_inflight, 100) >=
		    uwg_sat_mul(b->inflight_hi, 95)) {
			u64 step = max(b->inflight_hi / UWG_BBR_HI_GROWTH_DIVISOR,
				       b->mss);

			b->inflight_hi = uwg_sat_add(b->inflight_hi, step);
		}
		b->inflight_hi = max(b->inflight_hi, floor);
		b->inflight_lo = max(b->inflight_lo, uwg_mul_div(bdp, 3, 4));
		b->inflight_lo = min(b->inflight_lo, b->inflight_hi);
		b->inflight_lo = max(b->inflight_lo, b->min_cwnd);
	}

	b->inflight_hi = max(b->inflight_hi, b->min_cwnd);
	b->inflight_lo = min(b->inflight_lo, b->inflight_hi);
	b->inflight_lo = max(b->inflight_lo, min(b->min_cwnd, b->inflight_hi));
}

static void uwg_bbr_check_full_bw(struct uwg_bbr *b, u64 now_ns)
{
	u64 bw = b->btl_bw;

	if (uwg_sat_mul(bw, UWG_BBR_GAIN_UNIT) >=
	    uwg_sat_mul(b->full_bw, UWG_BBR_FULL_BW_THRESHOLD)) {
		b->full_bw = bw;
		b->full_bw_cnt = 0;
		return;
	}
	b->full_bw_cnt++;
	if (b->full_bw_cnt >= UWG_BBR_FULL_BW_ROUNDS)
		uwg_bbr_finish_startup(b, now_ns);
}

static void uwg_bbr_advance_cycle(struct uwg_bbr *b, u64 now_ns)
{
	bool was_probe_up = b->cycle_idx == 0;
	bool ended_clean;

	if (uwg_ns_sub(now_ns, b->cycle_start_ns) < uwg_bbr_phase_ns(b))
		return;

	ended_clean = !b->round_congestion && b->last_cut_round != b->round_count;
	b->cycle_idx = (b->cycle_idx + 1) % ARRAY_SIZE(uwg_bbr_cycle_gains);
	b->cycle_start_ns = now_ns;

	if (was_probe_up && ended_clean) {
		u64 observed = max(b->round_max_inflight, b->cwnd);

		b->inflight_hi = max(uwg_max3(b->inflight_hi, observed, b->min_cwnd),
				     b->min_cwnd);
		b->bw_hi = b->btl_bw;
	}
}

static void uwg_bbr_start_round(struct uwg_bbr *b, u64 now_ns)
{
	bool app_limited = uwg_sat_mul(b->round_max_inflight, 2) < b->cwnd;

	uwg_bbr_adapt_bounds(b);
	/*
	 * Plateau detection also runs on app-limited rounds: btl_bw is a
	 * windowed maximum, so a lull cannot lower it, and waiting for a
	 * full round would leave STARTUP stuck when the sender runs dry.
	 */
	if (b->mode == UWG_BBR_STARTUP && b->btl_bw)
		uwg_bbr_check_full_bw(b, now_ns);
	if (b->mode == UWG_BBR_PROBE_BW)
		uwg_bbr_advance_cycle(b, now_ns);

	b->round_count = uwg_sat_add(b->round_count, 1);
	b->round_delivered = 0;
	b->round_lost = 0;
	b->round_max_inflight = b->inflight;
	b->round_congestion = false;
	b->app_limited = app_limited;
	uwg_bw_round_start(b, !app_limited || b->round_count <= 1);
}

static void uwg_bbr_update_mode(struct uwg_bbr *b, u64 now_ns)
{
	if (b->mode == UWG_BBR_STARTUP && b->full_bw_reached) {
		b->mode = UWG_BBR_PROBE_BW;
		b->cycle_idx = 2;
		b->cycle_start_ns = now_ns;
	}
}

static void uwg_bbr_maybe_enter_probe_rtt(struct uwg_bbr *b, u64 now_ns)
{
	if (b->mode == UWG_BBR_PROBE_RTT || !b->min_rtt.seen_min)
		return;
	if (uwg_ns_sub(now_ns, b->min_rtt.stamp_ns) < UWG_BBR_MIN_RTT_WINDOW_NS)
		return;
	b->mode = UWG_BBR_PROBE_RTT;
	b->probe_rtt_start_ns = now_ns;
	b->probe_rtt_done_ns = uwg_sat_add(now_ns, UWG_BBR_PROBE_RTT_DURATION_NS);
	b->probe_rtt_round = b->round_count;
}

static void uwg_bbr_update_cwnd(struct uwg_bbr *b, u64 acked_bytes)
{
	u64 bdp = uwg_bbr_bdp(b);
	u64 target = uwg_mul_div(bdp, UWG_BBR_CWND_GAIN, UWG_BBR_GAIN_UNIT);
	u64 hi = max(b->inflight_hi, b->min_cwnd);
	u64 lo = max(min(b->inflight_lo, hi), b->min_cwnd);
	u64 cwnd;

	switch (b->mode) {
	case UWG_BBR_PROBE_RTT:
		cwnd = b->min_cwnd;
		break;
	case UWG_BBR_STARTUP: {
		u64 grown = uwg_sat_add(b->cwnd, acked_bytes);
		u64 cap = max(uwg_sat_mul(bdp, 4), b->min_cwnd);

		cwnd = max(grown, target);
		cwnd = min(cwnd, cap);
		cwnd = min(cwnd, hi);
		break;
	}
	case UWG_BBR_PROBE_BW: {
		u64 cap = hi;

		if (uwg_bbr_cycle_gains[b->cycle_idx %
					ARRAY_SIZE(uwg_bbr_cycle_gains)] >
		    UWG_BBR_GAIN_UNIT)
			cap = uwg_sat_add(hi, hi / 4);
		cwnd = max(target, lo);
		cwnd = min(cwnd, cap);
		break;
	}
	default:
		cwnd = max(target, lo);
		cwnd = min(cwnd, hi);
		break;
	}

	/*
	 * During a lossy round inflight_lo acts as a ceiling as well: without
	 * this the floor semantics below would immediately lift cwnd back to
	 * the uninflated target and the loss cut would have no effect. The
	 * cap stays for the round that follows a cut and never drops below
	 * one BDP, so persistent random loss cannot collapse the window and
	 * the BtlBw estimate with it.
	 */
	if (b->mode != UWG_BBR_STARTUP &&
	    (b->round_lost || b->round_congestion ||
	     (b->last_cut_round != U64_MAX &&
	      b->round_count == b->last_cut_round + 1))) {
		u64 loss_cap = max3(min(b->inflight_lo, b->inflight_hi),
				    uwg_bbr_bdp(b), b->min_cwnd);

		cwnd = min(cwnd, loss_cap);
	}

	cwnd = max(cwnd, b->min_cwnd);
	b->cwnd = min(cwnd, UWG_BBR_MAX_CWND);
}

static void uwg_bbr_probe_rtt_step(struct uwg_bbr *b, u64 now_ns)
{
	u64 elapsed;
	u64 rtt;
	bool drained;

	if (b->mode != UWG_BBR_PROBE_RTT)
		return;
	elapsed = uwg_ns_sub(now_ns, b->probe_rtt_start_ns);
	rtt = uwg_min_rtt_value(b);
	drained = b->inflight <= b->min_cwnd ||
		elapsed >= UWG_BBR_PROBE_RTT_DURATION_NS + rtt + uwg_bbr_phase_ns(b);
	if (elapsed < UWG_BBR_PROBE_RTT_DURATION_NS ||
	    now_ns < b->probe_rtt_done_ns || !drained ||
	    b->round_count <= b->probe_rtt_round)
		return;

	uwg_min_rtt_refresh(b, now_ns);
	b->mode = b->full_bw_reached ? UWG_BBR_PROBE_BW : UWG_BBR_STARTUP;
	b->cycle_idx = 1;
	b->cycle_start_ns = now_ns;
	b->bw_hi = b->btl_bw;
	uwg_bbr_update_cwnd(b, 0);
	uwg_bbr_update_pacing(b, now_ns);
}

static void uwg_bbr_note_loss(struct uwg_bbr *b, u64 len, u64 now_ns)
{
	u64 total;

	b->lost_bytes = uwg_sat_add(b->lost_bytes, len);
	b->lost_packets = uwg_sat_add(b->lost_packets, 1);
	b->round_lost = uwg_sat_add(b->round_lost, len);

	total = uwg_sat_add(b->round_delivered, b->round_lost);
	/* Random loss on a fat pipe is not congestion: only a loss rate above
	 * the threshold may drive the bounds or a cut, otherwise a steady 2%
	 * loss would shrink the window on every round.
	 */
	if (total &&
	    uwg_sat_mul(b->round_lost, 100) >=
	    uwg_sat_mul(total, UWG_BBR_LOSS_THRESHOLD_PCT)) {
		b->round_congestion = true;
		if (b->last_cut_round != b->round_count)
			uwg_bbr_apply_loss_cut(b, now_ns);
	}
}

static u64 uwg_bbr_sanity_rate(const struct uwg_bbr *b, u64 rate)
{
	u64 rtt = max(uwg_min_rtt_value(b), UWG_BBR_MIN_RTT_SAMPLE_NS);
	u64 cwnd = max(b->cwnd, b->min_cwnd);
	u64 bound = uwg_mul_div(cwnd, UWG_BBR_NSEC_PER_SEC, rtt);

	bound = uwg_mul_div(bound, UWG_BBR_RATE_SANITY_GAIN,
			    UWG_BBR_RATE_SANITY_UNIT);
	return min(min(rate, max(bound, 1ULL)), UWG_BBR_MAX_RATE);
}

static u64 uwg_bbr_rate_sample(const struct uwg_bbr *b,
			       const struct uwg_bbr_sent *newest,
			       u64 delivered_since, u64 now_ns, u64 delay_ns)
{
	u64 interval;
	u64 raw;

	if (!delivered_since)
		return 0;
	interval = uwg_subtract_delay(uwg_ns_sub(now_ns, newest->sent_ns), delay_ns);
	raw = uwg_mul_div(delivered_since, UWG_BBR_NSEC_PER_SEC, max(interval, 1ULL));
	raw = uwg_compensate_loss(raw, b->delivered, b->lost_bytes);
	return uwg_bbr_sanity_rate(b, raw);
}

static bool uwg_bbr_acknowledge(struct uwg_bbr *b, u64 largest, u64 bitmap,
				struct uwg_bbr_sent *newest, bool *have_newest)
{
	u64 bytes = 0;
	u64 bits = bitmap;
	unsigned int bit;
	int res;

	*have_newest = false;
	for (bit = 0; bit < 64 && bits; bit++, bits >>= 1) {
		struct uwg_bbr_sent slot;
		u64 counter;

		if (!(bits & 1))
			continue;
		if (largest < (u64)bit)
			continue;
		counter = largest - (u64)bit;
		res = uwg_ring_mark_acked(b, counter, &slot);
		if (!res)
			continue;
		if (res == 2)
			b->spurious_losses = uwg_sat_add(b->spurious_losses, 1);
		bytes = uwg_sat_add(bytes, slot.len);
		if (!*have_newest || slot.sent_ns >= newest->sent_ns) {
			*newest = slot;
			*have_newest = true;
		}
	}

	if (bytes) {
		b->delivered = uwg_sat_add(b->delivered, bytes);
		b->inflight = b->inflight > bytes ? b->inflight - bytes : 0;
		b->round_delivered = uwg_sat_add(b->round_delivered, bytes);
	}
	return *have_newest;
}

void uwg_bbr_init(struct uwg_bbr *b, u32 mss, u32 initial_rtt_us)
{
	u64 mss64 = mss ? mss : UWG_BBR_DEFAULT_MSS;
	u64 rtt_ns = (u64)initial_rtt_us * 1000ULL;

	if (rtt_ns < UWG_BBR_MIN_RTT_SAMPLE_NS)
		rtt_ns = UWG_BBR_MIN_RTT_SAMPLE_NS;

	memset(b, 0, sizeof(*b));
	b->mss = mss64;
	b->min_cwnd = mss64 * UWG_BBR_MIN_CWND_PACKETS;
	b->initial_rtt_ns = rtt_ns;
	b->initial_rate = max(uwg_mul_div(b->min_cwnd, UWG_BBR_NSEC_PER_SEC, rtt_ns), 1ULL);
	b->mode = UWG_BBR_STARTUP;
	b->cwnd = b->min_cwnd;
	b->pacing_rate = b->initial_rate;
	b->inflight_hi = U64_MAX;
	b->last_cut_round = U64_MAX;

	b->pacer.rate = b->initial_rate;
	b->pacer.mss = mss64;
	b->pacer.burst = uwg_pacer_burst(b->initial_rate, mss64);
	b->pacer.allowance = (s64)b->pacer.burst;
}

void uwg_bbr_new_epoch(struct uwg_bbr *b, u64 keypair_id, u64 now_ns)
{
	u64 delivered = b->delivered;

	/*
	 * A rekey restarts the nonce space at zero. The old records can never
	 * be acknowledged by the peer again, so drop them instead of leaving
	 * them to be matched by counters of the new keypair. The channel
	 * estimate (btl_bw, min_rtt, cwnd, pacing rate) describes the path and
	 * survives the rekey: resetting cwnd would either underutilise the
	 * link or cause a burst, neither of which the new keypair justifies.
	 */
	memset(b->ring, 0, sizeof(b->ring));
	b->epoch++;
	b->keypair_id = keypair_id;
	b->base_counter = 0;
	b->inflight = 0;
	b->largest_acked = 0;
	b->max_sent = 0;
	b->oldest_inflight = 0;
	b->oldest_valid = false;
	b->round_delivered = 0;
	b->round_lost = 0;
	b->round_max_inflight = 0;
	b->round_congestion = false;
	b->next_round_delivered = delivered;
	uwg_pacer_refill(b, now_ns);
}

/*
 * Fallback for a missed keypair notification: a changed id or a counter far
 * below max_sent cannot belong to the current nonce space, because the ring
 * only ever covers UWG_BBR_RING_CAPACITY counters. Nonces never wrap in
 * practice -- the protocol rejects a keypair long before 2^64 packets.
 */
static void uwg_bbr_maybe_new_epoch(struct uwg_bbr *b, u64 keypair_id,
				    u64 counter, u64 now_ns)
{
	if (unlikely(b->keypair_id != keypair_id)) {
		uwg_bbr_new_epoch(b, keypair_id, now_ns);
		return;
	}
	if (unlikely(b->max_sent > counter &&
		     b->max_sent - counter > UWG_BBR_RING_CAPACITY))
		uwg_bbr_new_epoch(b, keypair_id, now_ns);
}

void uwg_bbr_snapshot_get(const struct uwg_bbr *b,
			  struct uwg_bbr_snapshot *snap)
{
	snap->mode = b->mode;
	snap->cwnd = b->cwnd;
	snap->inflight = b->inflight;
	snap->pacing_rate = b->pacing_rate;
	snap->btl_bw = b->btl_bw;
	snap->min_rtt_ns = b->min_rtt.seen_min ? b->min_rtt.min_ns : 0;
	snap->round_lost = b->round_lost;
}

void uwg_bbr_on_send(struct uwg_bbr *b, u64 keypair_id, u64 counter, u32 len,
		     u64 now_ns)
{
	u32 evicted;

	uwg_bbr_maybe_new_epoch(b, keypair_id, counter, now_ns);

	/* Bound the record so the 2^29 delivered window always covers the ring. */
	if (!len)
		len = 1;
	else if (len > UWG_BBR_MAX_DATAGRAM)
		len = UWG_BBR_MAX_DATAGRAM;

	b->max_sent = max(b->max_sent, counter);
	uwg_pacer_refill(b, now_ns);

	evicted = uwg_ring_insert(b, counter, len, now_ns);
	if (evicted) {
		b->inflight = b->inflight > evicted ? b->inflight - evicted : 0;
		b->orphaned_packets = uwg_sat_add(b->orphaned_packets, 1);
	}
	b->inflight = uwg_sat_add(b->inflight, len);
	b->round_max_inflight = max(b->round_max_inflight, b->inflight);
	if (!b->oldest_valid || counter < b->oldest_inflight) {
		b->oldest_inflight = counter;
		b->oldest_valid = true;
	} else {
		/* An eviction may have removed the previous watermark. */
		uwg_ring_advance_oldest(b);
	}
	uwg_pacer_consume(b, len);
}

/*
 * Registers a wire counter that consumes nonce space without being tracked
 * in the send ring (control frames, keepalives). It only raises max_sent so
 * their ACKs pass the validation in uwg_bbr_on_ack().
 */
void uwg_bbr_note_sent(struct uwg_bbr *b, u64 keypair_id, u64 counter)
{
	uwg_bbr_maybe_new_epoch(b, keypair_id, counter, ktime_get_ns());
	b->max_sent = max(b->max_sent, counter);
}

void uwg_bbr_on_ack(struct uwg_bbr *b, u64 keypair_id, u64 largest,
		    u64 bitmap, u32 ack_delay_us, u64 now_ns)
{
	struct uwg_bbr_sent newest;
	bool have_newest;
	u64 prior_delivered;
	u64 newly_acked;
	u64 delay_ns;
	u64 delivered_since = 0;
	u64 rate = 0;
	bool have_rate = false;
	bool starts_round;

	/* An ACK is delivered on the keypair that carried the data it refers
	 * to. Feedback from any other keypair belongs to an earlier epoch and
	 * must not touch largest_acked, the ring, inflight or btl_bw.
	 */
	if (unlikely(keypair_id != b->keypair_id))
		return;

	/* A peer cannot acknowledge a counter we never put on the wire: such an
	 * ACK would drag largest_acked past the ring, release every in-flight
	 * record and zero inflight. Reject it before touching any state.
	 */
	if (unlikely(largest > b->max_sent))
		return;
	if (unlikely(largest < b->base_counter))
		return;

	/* Counters never regress within one keypair, so feedback far below
	 * largest_acked was produced by the previous keypair's nonce space.
	 * Ignoring it keeps the new epoch's largest_acked/inflight intact.
	 */
	if (unlikely(b->largest_acked > largest &&
		     b->largest_acked - largest > UWG_BBR_RING_CAPACITY))
		return;

	/* A bogus delay distorts the delivery-rate sample; one second is far
	 * above any plausible path delay and still bounded.
	 */
	ack_delay_us = min_t(u32, ack_delay_us, NSEC_PER_SEC / 1000);

	uwg_pacer_refill(b, now_ns);
	b->largest_acked = max(b->largest_acked, largest);

	prior_delivered = b->delivered;
	uwg_bbr_acknowledge(b, largest, bitmap, &newest, &have_newest);
	newly_acked = b->delivered - prior_delivered;

	uwg_ring_release_unreachable(b, largest, now_ns);
	uwg_ring_note_holes(b, largest, bitmap, now_ns);
	uwg_ring_advance_oldest(b);

	delay_ns = uwg_delay_ns(ack_delay_us);

	if (have_newest) {
		u64 raw = uwg_ns_sub(now_ns, newest.sent_ns);

		uwg_min_rtt_sample(b, uwg_rtt_sample(raw, delay_ns), now_ns);
		if (newly_acked) {
			delivered_since = uwg_delivered_since(b, &newest);
			rate = uwg_bbr_rate_sample(b, &newest, delivered_since,
						   now_ns, delay_ns);
			have_rate = rate > 0;
		}
	}

	starts_round = newly_acked > 0 && have_newest &&
		b->next_round_delivered <= b->delivered &&
		delivered_since <= b->delivered - b->next_round_delivered;

	if (starts_round) {
		uwg_bbr_start_round(b, now_ns);
		b->next_round_delivered = b->delivered;
	}

	if (have_rate) {
		uwg_bw_add(b, rate);
		b->btl_bw = min(uwg_bw_max(b), UWG_BBR_MAX_RATE);
	}

	uwg_bbr_update_mode(b, now_ns);
	uwg_bbr_maybe_enter_probe_rtt(b, now_ns);
	uwg_bbr_probe_rtt_step(b, now_ns);
	uwg_bbr_update_cwnd(b, newly_acked);
	uwg_bbr_update_pacing(b, now_ns);
}

void uwg_bbr_on_loss(struct uwg_bbr *b, u64 counter, u64 now_ns)
{
	u32 len = 0;
	int state;

	/* Nothing outside [base_counter, max_sent] was sent in this nonce
	 * space: this is feedback for an older keypair and must not touch the
	 * new epoch.
	 */
	if (unlikely(counter > b->max_sent || counter < b->base_counter))
		return;

	uwg_pacer_refill(b, now_ns);

	state = uwg_ring_mark_lost(b, counter, &len);
	if (state == 1) {
		b->inflight = b->inflight > len ? b->inflight - len : 0;
		uwg_bbr_note_loss(b, len, now_ns);
	} else if (state == 2) {
		/* The ACK bitmap already reported this hole. */
		b->inflight = b->inflight > len ? b->inflight - len : 0;
	} else if (state == 3) {
		/* Dropped locally: the bytes already left inflight. */
	} else if (state == 4) {
		/* Loss was already counted by the bitmap or the watermark. */
	} else {
		bool unreachable = counter < b->largest_acked &&
			b->largest_acked - counter > UWG_BBR_ACK_WINDOW;

		if (unreachable)
			uwg_bbr_note_loss(b, b->mss, now_ns);
		else
			b->spurious_losses = uwg_sat_add(b->spurious_losses, 1);
	}

	uwg_ring_advance_oldest(b);
	uwg_bbr_update_cwnd(b, 0);
	uwg_bbr_update_pacing(b, now_ns);
}

/*
 * Returns the bytes of a locally dropped datagram to the congestion window
 * without treating the drop as a delivery or as a congestion signal. Must
 * be called after uwg_bbr_on_send() and before the skb is freed.
 */
void uwg_bbr_on_drop(struct uwg_bbr *b, u64 counter)
{
	struct uwg_bbr_sent *slot;

	if (unlikely(counter > b->max_sent || counter < b->base_counter))
		return;

	slot = &b->ring[counter & UWG_BBR_RING_MASK];
	if (slot->counter != counter || !uwg_slot_inflight(slot))
		return;

	if (b->inflight > slot->len)
		b->inflight -= slot->len;
	else
		b->inflight = 0;
	uwg_slot_set_state(slot, UWG_BBR_SLOT_DROPPED);
	uwg_ring_advance_oldest(b);
}

/*
 * Token-bucket pacing query: how long the caller should wait before handing
 * len bytes to the device so that the burst does not exceed the pacing rate.
 * The projection is read-only: credit for len bytes is charged when the
 * datagram is registered through uwg_bbr_on_send(), so querying twice for
 * the same datagram yields the same delay and never starves the bucket.
 */
void uwg_bbr_on_sent(struct uwg_bbr *b, u64 counter, u64 now_ns)
{
	struct uwg_bbr_sent *slot;

	if (unlikely(counter > b->max_sent || counter < b->base_counter))
		return;

	slot = &b->ring[counter & UWG_BBR_RING_MASK];
	if (slot->counter == counter &&
	    uwg_slot_state(slot) == UWG_BBR_SLOT_INFLIGHT)
		slot->sent_ns = now_ns;
}

u64 uwg_bbr_next_delay_ns(struct uwg_bbr *b, u32 len, u64 now_ns)
{
	const struct uwg_bbr_pacer *p = &b->pacer;
	s64 allowance;
	u64 deficit;
	u64 delay = 0;
	u64 rate;

	if (!len)
		return 0;
	if (len > UWG_BBR_MAX_DATAGRAM)
		len = UWG_BBR_MAX_DATAGRAM;

	allowance = uwg_pacer_projected_allowance(p, now_ns);
	if (allowance < (s64)len) {
		if (allowance >= 0)
			deficit = (u64)len - (u64)allowance;
		else
			deficit = uwg_sat_add((u64)len, (u64)(-allowance));

		rate = max(p->rate, 1ULL);
		delay = uwg_mul_div(deficit, UWG_BBR_NSEC_PER_SEC, rate);
	}

	/*
	 * The congestion window is enforced by the sender, which withholds
	 * packets instead of sleeping on them: on low-RTT links cwnd is a few
	 * KiB and a per-batch drain delay turned into a hard throughput
	 * ceiling. Here only the token bucket is applied.
	 */

	return delay;
}

u64 uwg_bbr_pacing_rate(const struct uwg_bbr *b)
{
	return b->pacing_rate;
}

u64 uwg_bbr_cwnd(const struct uwg_bbr *b)
{
	return b->cwnd;
}

u64 uwg_bbr_inflight(const struct uwg_bbr *b)
{
	return b->inflight;
}

u64 uwg_bbr_effective_cwnd(const struct uwg_bbr *b)
{
	u64 floor = uwg_mul_div(b->pacing_rate, UWG_BBR_CWND_FLOOR_NS,
				UWG_BBR_NSEC_PER_SEC);

	return max(b->cwnd, min(floor, UWG_BBR_CWND_FLOOR_MAX));
}

u64 uwg_bbr_cwnd_allowance(const struct uwg_bbr *b)
{
	u64 cwnd = uwg_bbr_effective_cwnd(b);
	u64 inflight = b->inflight;

	return cwnd > inflight ? cwnd - inflight : 0;
}

bool uwg_bbr_full_bw_reached(const struct uwg_bbr *b)
{
	return b->full_bw_reached;
}

bool uwg_bbr_loss_limited(const struct uwg_bbr *b)
{
	return b->inflight_hi < b->cwnd;
}

/* ------------------------------------------------------------------------- */
/* Self-test                                                                  */
/* ------------------------------------------------------------------------- */

struct uwg_bbr_sim_pkt {
	u64 event_ns;
	u32 len;
	bool lost;
	bool delivered;
	bool done;
};

struct uwg_bbr_sim_params {
	u32 packets;
	u32 loss_period;
	u32 burst_start;
	u32 burst_len;
	u32 mss;
	u64 capacity;
	u64 prop_ns;
	u32 ack_delay_us;
};

struct uwg_bbr_sim_result {
	u64 neutral_rate;
	u64 peak_rate;
	u32 sent;
	bool saw_neutral;
	bool drained;
};

#define UWG_BBR_SIM_CAPACITY 12500000ULL	/* 100 Mbit/s */
#define UWG_BBR_SIM_PROP_NS 10000000ULL		/* 10 ms one way */
#define UWG_BBR_SIM_PACKETS 3000U
#define UWG_BBR_SIM_ITER_LIMIT 4000000ULL

static bool uwg_bbr_sim_lost(const struct uwg_bbr_sim_params *p, u32 counter)
{
	if (p->loss_period && (counter + 1) % p->loss_period == 0)
		return true;
	return p->burst_len && counter >= p->burst_start &&
	       counter < p->burst_start + p->burst_len;
}

static int uwg_bbr_sim(struct uwg_bbr *b, const struct uwg_bbr_sim_params *p,
		       struct uwg_bbr_sim_result *res)
{
	struct uwg_bbr_sim_pkt *pkt;
	u64 now = 0;
	u64 bottleneck_free = 0;
	u64 next_send = 0;
	u64 largest_received = 0;
	u32 sent = 0;
	u32 completed = 0;
	u64 iterations = 0;

	memset(res, 0, sizeof(*res));
	pkt = kcalloc(p->packets, sizeof(*pkt), GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;

	while ((sent < p->packets || completed < sent) &&
	       iterations++ < UWG_BBR_SIM_ITER_LIMIT) {
		while (sent < p->packets) {
			u64 cwnd = uwg_bbr_cwnd(b);
			u64 inflight = uwg_bbr_inflight(b);
			u64 rate;
			u64 interval;
			u64 depart;
			u64 rtt_ns;
			bool lost;

			if (inflight + p->mss > cwnd)
				break;
			if (now < next_send)
				break;

			lost = uwg_bbr_sim_lost(p, sent);
			pkt[sent].len = p->mss;
			pkt[sent].lost = lost;
			pkt[sent].delivered = !lost;
			uwg_bbr_on_send(b, b->keypair_id, sent, p->mss, now);

			depart = max(now, bottleneck_free);
			bottleneck_free = depart +
				div64_u64((u64)p->mss * UWG_BBR_NSEC_PER_SEC, p->capacity);
			rtt_ns = 2 * p->prop_ns;
			if (lost) {
				/*
				 * A loss is only reported once the FEC recovery
				 * window closes, three RTTs after the send.
				 */
				pkt[sent].event_ns = uwg_sat_add(depart, 3 * rtt_ns);
			} else {
				pkt[sent].event_ns = uwg_sat_add(depart, rtt_ns);
				pkt[sent].event_ns = uwg_sat_add(pkt[sent].event_ns,
								 (u64)p->ack_delay_us * 1000ULL);
			}

			rate = max(uwg_bbr_pacing_rate(b), 1ULL);
			interval = max(div64_u64((u64)p->mss * UWG_BBR_NSEC_PER_SEC, rate), 1ULL);
			next_send = uwg_sat_add(now, interval);
			sent++;
		}

		{
			u64 next_event = U64_MAX;
			u64 min_event = U64_MAX;
			u32 next_idx = 0;
			bool have_event = false;
			u32 i;

			for (i = 0; i < sent; i++) {
				if (pkt[i].done)
					continue;
				if (!have_event || pkt[i].event_ns < min_event) {
					min_event = pkt[i].event_ns;
					next_idx = i;
					have_event = true;
				}
			}

			if (have_event)
				next_event = min(next_event, min_event);
			if (sent < p->packets &&
			    uwg_bbr_inflight(b) + p->mss <= uwg_bbr_cwnd(b))
				next_event = min(next_event, next_send);
			if (next_event == U64_MAX)
				break;
			if (next_event > now) {
				now = next_event;
				continue;
			}
			if (!have_event || min_event > now)
				break;

			pkt[next_idx].done = true;
			completed++;
			if (pkt[next_idx].lost) {
				uwg_bbr_on_loss(b, next_idx, now);
			} else {
				u64 bitmap = 0;
				u32 j;

				largest_received = max(largest_received, (u64)next_idx);
				for (j = 0; j <= UWG_BBR_ACK_WINDOW; j++) {
					if (largest_received < (u64)j)
						break;
					if (pkt[largest_received - j].delivered)
						bitmap |= 1ULL << j;
				}
				uwg_bbr_on_ack(b, b->keypair_id, largest_received, bitmap,
					       p->ack_delay_us, now);
			}

			res->peak_rate = max(res->peak_rate, b->pacing_rate);
			if (b->mode == UWG_BBR_PROBE_BW &&
			    uwg_bbr_cycle_gains[b->cycle_idx % ARRAY_SIZE(uwg_bbr_cycle_gains)] ==
				    UWG_BBR_GAIN_UNIT) {
				res->neutral_rate = b->pacing_rate;
				res->saw_neutral = true;
			}
		}
	}

	res->sent = sent;
	res->drained = completed == sent && b->inflight == 0;
	kfree(pkt);

	if (completed != sent)
		return -EINVAL;
	return 0;
}

static int uwg_bbr_selftest_path(void)
{
	struct uwg_bbr_sim_params params = {
		.packets = UWG_BBR_SIM_PACKETS,
		.loss_period = 50,
		.burst_start = 0,
		.burst_len = 0,
		.mss = UWG_BBR_DEFAULT_MSS,
		.capacity = UWG_BBR_SIM_CAPACITY,
		.prop_ns = UWG_BBR_SIM_PROP_NS,
		.ack_delay_us = 0,
	};
	struct uwg_bbr_sim_result res;
	struct uwg_bbr *b;
	u64 low = UWG_BBR_SIM_CAPACITY * 90 / 100;
	u64 high = UWG_BBR_SIM_CAPACITY * 110 / 100;
	int ret;

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return -ENOMEM;

	uwg_bbr_init(b, params.mss, 20000);
	ret = uwg_bbr_sim(b, &params, &res);
	if (ret < 0) {
		pr_err("BBR self-test: simulation did not drain: %d\n", ret);
		goto out;
	}

	if (!res.saw_neutral || res.neutral_rate < low || res.neutral_rate > high) {
		pr_err("BBR self-test: rate %llu outside %llu..%llu\n",
		       res.neutral_rate, low, high);
		ret = -EINVAL;
		goto out;
	}
	if (b->btl_bw < low || b->btl_bw > high) {
		pr_err("BBR self-test: BtlBw %llu outside %llu..%llu\n",
		       b->btl_bw, low, high);
		ret = -EINVAL;
		goto out;
	}
	if (!b->cwnd || !b->pacing_rate || b->mode != UWG_BBR_PROBE_BW) {
		pr_err("BBR self-test: bad state (cwnd=%llu rate=%llu mode=%u)\n",
		       b->cwnd, b->pacing_rate, b->mode);
		ret = -EINVAL;
		goto out;
	}
	/* The simulated path found the full pipe: the cwnd gate is armed. */
	if (!uwg_bbr_full_bw_reached(b)) {
		pr_err("BBR self-test: PROBE_BW without full_bw_reached\n");
		ret = -EINVAL;
		goto out;
	}
	if (!res.drained || uwg_bbr_inflight(b) != 0) {
		pr_err("BBR self-test: inflation not released (%llu)\n",
		       uwg_bbr_inflight(b));
		ret = -EINVAL;
		goto out;
	}
	if (!b->lost_packets || b->inflight_lo > b->inflight_hi) {
		pr_err("BBR self-test: loss accounting broken (lost=%llu lo=%llu hi=%llu)\n",
		       b->lost_packets, b->inflight_lo, b->inflight_hi);
		ret = -EINVAL;
		goto out;
	}

out:
	kfree(b);
	return ret;
}

static int uwg_bbr_selftest_clean(void)
{
	struct uwg_bbr_sim_params params = {
		.packets = UWG_BBR_SIM_PACKETS,
		.loss_period = 0,
		.burst_start = 0,
		.burst_len = 0,
		.mss = UWG_BBR_DEFAULT_MSS,
		.capacity = UWG_BBR_SIM_CAPACITY,
		.prop_ns = UWG_BBR_SIM_PROP_NS,
		.ack_delay_us = 0,
	};
	struct uwg_bbr_sim_result res;
	struct uwg_bbr *b;
	u64 low = UWG_BBR_SIM_CAPACITY * 90 / 100;
	int ret;

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return -ENOMEM;

	uwg_bbr_init(b, params.mss, 20000);
	ret = uwg_bbr_sim(b, &params, &res);
	if (ret < 0) {
		pr_err("BBR self-test: clean path did not drain: %d\n", ret);
		goto out;
	}
	if (b->btl_bw < low) {
		pr_err("BBR self-test: clean BtlBw %llu below %llu\n",
		       b->btl_bw, low);
		ret = -EINVAL;
		goto out;
	}
	if (!res.drained || uwg_bbr_inflight(b) != 0 || !b->cwnd ||
	    b->lost_packets || b->spurious_losses) {
		pr_err("BBR self-test: clean path accounting broken\n");
		ret = -EINVAL;
		goto out;
	}
	/*
	 * A clean path never cuts inflight_hi, so the sender must not gate on
	 * the window there: the pacer, not the ACK cadence, sets the rate.
	 */
	if (uwg_bbr_loss_limited(b)) {
		pr_err("BBR self-test: clean path armed the cwnd gate (hi=%llu cwnd=%llu)\n",
		       b->inflight_hi, uwg_bbr_cwnd(b));
		ret = -EINVAL;
		goto out;
	}

out:
	kfree(b);
	return ret;
}

static int uwg_bbr_selftest_burst(void)
{
	struct uwg_bbr_sim_params params = {
		.packets = 600,
		.loss_period = 0,
		.burst_start = 300,
		.burst_len = 10,
		.mss = UWG_BBR_DEFAULT_MSS,
		.capacity = UWG_BBR_SIM_CAPACITY,
		.prop_ns = UWG_BBR_SIM_PROP_NS,
		.ack_delay_us = 0,
	};
	struct uwg_bbr_sim_result res;
	struct uwg_bbr *b;
	int ret;

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return -ENOMEM;

	uwg_bbr_init(b, params.mss, 20000);
	ret = uwg_bbr_sim(b, &params, &res);
	if (ret < 0) {
		pr_err("BBR self-test: burst simulation stalled: %d\n", ret);
		goto out;
	}
	if (res.sent < params.packets || !res.drained) {
		pr_err("BBR self-test: burst left %llu bytes in flight\n",
		       uwg_bbr_inflight(b));
		ret = -EINVAL;
		goto out;
	}
	if (!uwg_bbr_pacing_rate(b) || !uwg_bbr_cwnd(b)) {
		pr_err("BBR self-test: loss burst zeroed the controller\n");
		ret = -EINVAL;
		goto out;
	}
	if (b->spurious_losses) {
		pr_err("BBR self-test: %llu spurious losses\n", b->spurious_losses);
		ret = -EINVAL;
		goto out;
	}

out:
	kfree(b);
	return ret;
}

static int uwg_bbr_selftest_edges(void)
{
	struct uwg_bbr *b;
	u64 i;
	u64 delay;

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return -ENOMEM;

	uwg_bbr_init(b, 0, 0);
	if (b->mss != UWG_BBR_DEFAULT_MSS ||
	    b->initial_rtt_ns != UWG_BBR_MIN_RTT_SAMPLE_NS ||
	    b->min_cwnd != UWG_BBR_DEFAULT_MSS * UWG_BBR_MIN_CWND_PACKETS ||
	    !b->pacing_rate || b->cwnd != b->min_cwnd) {
		pr_err("BBR self-test: zero config not sanitised\n");
		kfree(b);
		return -EINVAL;
	}
	/* A fresh controller is in STARTUP: the sender must not gate on it. */
	if (uwg_bbr_full_bw_reached(b)) {
		pr_err("BBR self-test: STARTUP already reported a full pipe\n");
		kfree(b);
		return -EINVAL;
	}

	/* A bitmap that covers nothing and a zero-length send are no-ops. */
	uwg_bbr_on_send(b, b->keypair_id, 0, 0, 1000);
	uwg_bbr_on_ack(b, b->keypair_id, 0, 0, 0, 2000);
	if (uwg_bbr_inflight(b) != 1) {
		pr_err("BBR self-test: zero-length send mis-accounted\n");
		kfree(b);
		return -EINVAL;
	}
	uwg_bbr_on_ack(b, b->keypair_id, 0, 1, 0, 3000);
	if (uwg_bbr_inflight(b) != 0) {
		pr_err("BBR self-test: single ACK did not clear inflight\n");
		kfree(b);
		return -EINVAL;
	}

	/* Loss reports for unknown and old counters must not corrupt state. */
	uwg_bbr_on_loss(b, 5000, 4000);
	uwg_bbr_on_loss(b, U64_MAX, 5000);
	uwg_bbr_on_loss(b, 0, 6000);
	if (!b->spurious_losses || b->lost_packets) {
		pr_err("BBR self-test: unknown loss classification broken\n");
		kfree(b);
		return -EINVAL;
	}

	/* Ring wrap: capacity + 1000 unacknowledged sends must stay bounded. */
	for (i = 0; i < UWG_BBR_RING_CAPACITY + 1000; i++)
		uwg_bbr_on_send(b, b->keypair_id, 100 + i, 1400, 10000 + i * 1000);
	if (!b->orphaned_packets || b->inflight > UWG_BBR_RING_CAPACITY * 1400ULL) {
		pr_err("BBR self-test: ring overflow accounting broken\n");
		kfree(b);
		return -EINVAL;
	}

	/* Ten seconds without a lower RTT sample must enter PROBE_RTT. */
	uwg_bbr_init(b, 1400, 20000);
	uwg_bbr_on_send(b, b->keypair_id, 0, 1400, 1000000000ULL);
	uwg_bbr_on_ack(b, b->keypair_id, 0, 1, 0, 1020000000ULL);
	uwg_bbr_on_send(b, b->keypair_id, 1, 1400, 11020000000ULL);
	uwg_bbr_on_ack(b, b->keypair_id, 1, 3, 0, 11040000000ULL);
	if (b->mode != UWG_BBR_PROBE_RTT || b->cwnd != b->min_cwnd) {
		pr_err("BBR self-test: PROBE_RTT not entered (mode=%u cwnd=%llu)\n",
		       b->mode, b->cwnd);
		kfree(b);
		return -EINVAL;
	}

	/* A huge peer-reported delay must not move the RTT floor. */
	uwg_bbr_init(b, 1400, 20000);
	uwg_bbr_on_send(b, b->keypair_id, 0, 1400, 1000000);
	uwg_bbr_on_ack(b, b->keypair_id, 0, 1, U32_MAX, 21000000);
	if (uwg_min_rtt_value(b) < UWG_BBR_MIN_RTT_SAMPLE_NS ||
	    uwg_min_rtt_value(b) > 20000000) {
		pr_err("BBR self-test: ACK delay clamped wrongly (%llu)\n",
		       uwg_min_rtt_value(b));
		kfree(b);
		return -EINVAL;
	}

	/*
	 * The pacer projection must report the deficit left by on_send()
	 * (1400 bytes already charged out of a 2800-byte burst) without
	 * consuming anything itself.
	 */
	uwg_bbr_init(b, 1400, 20000);
	uwg_bbr_on_send(b, b->keypair_id, 0, 1400, 1000);
	delay = uwg_bbr_next_delay_ns(b, 2800, 1000);
	if (delay != 5000000ULL) {
		pr_err("BBR self-test: pacing projection %llu, expected 5000000\n",
		       delay);
		kfree(b);
		return -EINVAL;
	}
	if (uwg_bbr_next_delay_ns(b, 2800, 1000) != delay ||
	    uwg_bbr_next_delay_ns(b, 0, 1000) != 0 ||
	    uwg_bbr_inflight(b) != 1400) {
		pr_err("BBR self-test: pacing projection is not read-only\n");
		kfree(b);
		return -EINVAL;
	}
	if (uwg_bbr_next_delay_ns(b, 2800, 1001000) >= delay) {
		pr_err("BBR self-test: pacing projection ignores refills\n");
		kfree(b);
		return -EINVAL;
	}

	/*
	 * A hole in the ACK bitmap is a loss of this round; a later ACK for
	 * the same counter is spurious and must not be counted twice.
	 */
	uwg_bbr_init(b, 1400, 20000);
	uwg_bbr_on_send(b, b->keypair_id, 0, 1400, 1000);
	uwg_bbr_on_send(b, b->keypair_id, 1, 1400, 1100);
	uwg_bbr_on_send(b, b->keypair_id, 2, 1400, 1200);
	uwg_bbr_on_ack(b, b->keypair_id, 2, 0x5, 0, 5000000);
	if (b->lost_packets != 1 || uwg_bbr_inflight(b) != 1400) {
		pr_err("BBR self-test: bitmap hole not seen as loss (lost=%llu inflight=%llu)\n",
		       b->lost_packets, uwg_bbr_inflight(b));
		kfree(b);
		return -EINVAL;
	}
	uwg_bbr_on_ack(b, b->keypair_id, 2, 0x7, 0, 6000000);
	if (b->lost_packets != 1 || !b->spurious_losses ||
	    uwg_bbr_inflight(b) != 0) {
		pr_err("BBR self-test: hole recovery mis-accounted (lost=%llu spurious=%llu inflight=%llu)\n",
		       b->lost_packets, b->spurious_losses,
		       uwg_bbr_inflight(b));
		kfree(b);
		return -EINVAL;
	}

	/* An explicit loss report for an already-counted hole is not a second loss. */
	uwg_bbr_init(b, 1400, 20000);
	uwg_bbr_on_send(b, b->keypair_id, 0, 1400, 1000);
	uwg_bbr_on_send(b, b->keypair_id, 1, 1400, 1100);
	uwg_bbr_on_ack(b, b->keypair_id, 1, 0x1, 0, 5000000);
	uwg_bbr_on_loss(b, 0, 6000000);
	if (b->lost_packets != 1 || uwg_bbr_inflight(b) != 0) {
		pr_err("BBR self-test: hole loss counted twice (lost=%llu inflight=%llu)\n",
		       b->lost_packets, uwg_bbr_inflight(b));
		kfree(b);
		return -EINVAL;
	}

	/* Locally dropped datagrams leave inflight but are not losses. */
	uwg_bbr_init(b, 1400, 20000);
	uwg_bbr_on_send(b, b->keypair_id, 0, 1400, 1000);
	uwg_bbr_on_drop(b, 0);
	if (uwg_bbr_inflight(b) != 0 || b->lost_packets) {
		pr_err("BBR self-test: local drop mis-accounted\n");
		kfree(b);
		return -EINVAL;
	}
	uwg_bbr_on_loss(b, 0, 2000);
	if (b->lost_packets) {
		pr_err("BBR self-test: dropped datagram counted as loss\n");
		kfree(b);
		return -EINVAL;
	}

	/*
	 * Records that fall out of the 64-bit ACK window without being
	 * acknowledged are losses and must be released through the watermark,
	 * not left in inflight forever.
	 */
	uwg_bbr_init(b, 1400, 20000);
	for (i = 0; i < 100; i++)
		uwg_bbr_on_send(b, b->keypair_id, i, 1400, 1000000 + i * 1000);
	uwg_bbr_on_ack(b, b->keypair_id, 99, U64_MAX, 0, 2000000);
	if (uwg_bbr_inflight(b) != 0 || b->lost_packets != 36) {
		pr_err("BBR self-test: watermark release broken (lost=%llu inflight=%llu)\n",
		       b->lost_packets, uwg_bbr_inflight(b));
		kfree(b);
		return -EINVAL;
	}

	/* The pacer must not fold cwnd into the delay: the sender gates on it. */
	uwg_bbr_init(b, 1400, 20000);
	for (i = 0; i < 5; i++)
		uwg_bbr_on_send(b, b->keypair_id, i, 1400, 1000 + i);
	delay = uwg_bbr_next_delay_ns(b, 1400, 1000);
	if (delay != 15000000ULL) {
		pr_err("BBR self-test: pure pacing delay %llu, expected 15000000\n",
		       delay);
		kfree(b);
		return -EINVAL;
	}

	kfree(b);
	return 0;
}

static int uwg_bbr_selftest_epoch(void)
{
	struct uwg_bbr *b;
	u64 btl_bw, min_rtt, cwnd, rate, lost;
	unsigned int i;

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return -ENOMEM;

	uwg_bbr_init(b, 1400, 20000);
	uwg_bbr_on_send(b, b->keypair_id, 0, 1400, 1000000);
	uwg_bbr_on_ack(b, b->keypair_id, 0, 1, 0, 2000000);
	uwg_bbr_on_send(b, b->keypair_id, 1, 1400, 2100000);
	uwg_bbr_on_ack(b, b->keypair_id, 1, 1, 0, 3100000);
	if (!b->btl_bw || !b->min_rtt.seen_min || uwg_bbr_inflight(b)) {
		pr_err("BBR self-test: epoch fixture did not converge\n");
		kfree(b);
		return -EINVAL;
	}

	btl_bw = b->btl_bw;
	min_rtt = b->min_rtt.min_ns;
	cwnd = uwg_bbr_cwnd(b);
	rate = uwg_bbr_pacing_rate(b);
	lost = b->lost_packets;

	uwg_bbr_new_epoch(b, 42, 4000000);
	if (b->epoch != 1 || uwg_bbr_inflight(b) || b->largest_acked ||
	    b->max_sent || b->oldest_valid || b->round_lost ||
	    b->round_delivered) {
		pr_err("BBR self-test: new epoch left stale counters\n");
		kfree(b);
		return -EINVAL;
	}
	for (i = 0; i < UWG_BBR_RING_CAPACITY; i++) {
		if (uwg_slot_state(&b->ring[i]) != UWG_BBR_SLOT_EMPTY) {
			pr_err("BBR self-test: new epoch left slot %u dirty\n", i);
			kfree(b);
			return -EINVAL;
		}
	}
	if (b->btl_bw != btl_bw || b->min_rtt.min_ns != min_rtt ||
	    uwg_bbr_cwnd(b) != cwnd || uwg_bbr_pacing_rate(b) != rate) {
		pr_err("BBR self-test: new epoch lost the channel estimate\n");
		kfree(b);
		return -EINVAL;
	}

	/* Feedback carried on another keypair must not move the new epoch's
	 * largest_acked, inflight, loss counters or the bandwidth estimate.
	 */
	uwg_bbr_on_ack(b, 41, 7000, U64_MAX, 0, 5000000);
	uwg_bbr_on_loss(b, 7000, 5000000);
	uwg_bbr_on_drop(b, 7000);
	if (b->largest_acked || uwg_bbr_inflight(b) || b->btl_bw != btl_bw ||
	    b->lost_packets != lost || b->spurious_losses) {
		pr_err("BBR self-test: stale feedback reached the new epoch\n");
		kfree(b);
		return -EINVAL;
	}

	uwg_bbr_on_send(b, 42, 0, 1400, 6000000);
	uwg_bbr_on_loss(b, 8000, 6100000);
	if (uwg_bbr_inflight(b) != 1400 || b->lost_packets != lost) {
		pr_err("BBR self-test: stale loss corrupted the new epoch\n");
		kfree(b);
		return -EINVAL;
	}
	/* The same counter, but issued on the old keypair: the ring record of
	 * the new epoch must stay in flight.
	 */
	uwg_bbr_on_ack(b, 41, 0, 1, 0, 6500000);
	if (uwg_bbr_inflight(b) != 1400 || b->largest_acked ||
	    b->btl_bw != btl_bw) {
		pr_err("BBR self-test: ACK from a foreign keypair was applied\n");
		kfree(b);
		return -EINVAL;
	}
	uwg_bbr_on_ack(b, 42, 0, 1, 0, 7000000);
	if (uwg_bbr_inflight(b) != 0 || b->largest_acked != 0) {
		pr_err("BBR self-test: new epoch ACK not applied\n");
		kfree(b);
		return -EINVAL;
	}

	/* A counter space restart without a keypair notification is detected
	 * from the nonce regression itself.
	 */
	uwg_bbr_init(b, 1400, 20000);
	for (i = 0; i < UWG_BBR_RING_CAPACITY + 10; i++)
		uwg_bbr_on_send(b, b->keypair_id, i, 1400, 1000000 + i * 1000);
	uwg_bbr_on_send(b, b->keypair_id, 0, 1400, 9000000);
	if (b->epoch != 1 || uwg_bbr_inflight(b) != 1400 || b->max_sent) {
		pr_err("BBR self-test: nonce restart not detected (epoch=%u inflight=%llu max_sent=%llu)\n",
		       b->epoch, uwg_bbr_inflight(b), b->max_sent);
		kfree(b);
		return -EINVAL;
	}

	kfree(b);
	return 0;
}

/*
 * The sender's cwnd gate reads uwg_bbr_cwnd_allowance() under the peer's
 * bbr_lock: an empty window admits the whole effective cwnd, a saturated
 * one admits nothing, and an ACK must hand the window back.
 */
static int uwg_bbr_selftest_cwnd(void)
{
	struct uwg_bbr *b;
	u64 cwnd, inflight, nonce = 0;
	unsigned int i;

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return -ENOMEM;

	uwg_bbr_init(b, 1400, 20000);
	cwnd = uwg_bbr_cwnd(b);
	if (!cwnd || uwg_bbr_inflight(b)) {
		pr_err("BBR self-test: cwnd fixture not empty (cwnd=%llu inflight=%llu)\n",
		       cwnd, uwg_bbr_inflight(b));
		kfree(b);
		return -EINVAL;
	}
	if (uwg_bbr_cwnd_allowance(b) != cwnd) {
		pr_err("BBR self-test: empty window admits %llu of %llu\n",
		       uwg_bbr_cwnd_allowance(b), cwnd);
		kfree(b);
		return -EINVAL;
	}

	uwg_bbr_on_send(b, b->keypair_id, nonce, 1400, 1000);
	if (uwg_bbr_cwnd_allowance(b) != cwnd - 1400) {
		pr_err("BBR self-test: one datagram in flight leaves %llu, expected %llu\n",
		       uwg_bbr_cwnd_allowance(b), cwnd - 1400);
		kfree(b);
		return -EINVAL;
	}

	/* Fill the window: the gate must stop admitting new datagrams. */
	for (i = 1; i < 64 && uwg_bbr_inflight(b) < cwnd; i++)
		uwg_bbr_on_send(b, b->keypair_id, ++nonce, 1400,
				1000 + (u64)i * 1000);
	inflight = uwg_bbr_inflight(b);
	if (inflight < cwnd || uwg_bbr_cwnd_allowance(b)) {
		pr_err("BBR self-test: saturated window still admits %llu (inflight=%llu cwnd=%llu)\n",
		       uwg_bbr_cwnd_allowance(b), inflight, uwg_bbr_cwnd(b));
		kfree(b);
		return -EINVAL;
	}

	/* The ACK that drains inflight must reopen the window. */
	uwg_bbr_on_ack(b, b->keypair_id, nonce, 1, 0, 5000000);
	if (uwg_bbr_inflight(b) >= inflight || !uwg_bbr_cwnd_allowance(b)) {
		pr_err("BBR self-test: ACK did not reopen the window (inflight %llu -> %llu)\n",
		       inflight, uwg_bbr_inflight(b));
		kfree(b);
		return -EINVAL;
	}

	/*
	 * The effective window is floored at one worst-case ACK interval of
	 * pacing, never below the raw cwnd and never above the cap.
	 */
	uwg_bbr_init(b, 1400, 20000);
	if (uwg_bbr_effective_cwnd(b) != uwg_bbr_cwnd(b)) {
		pr_err("BBR self-test: floor lifted a large cwnd (%llu vs %llu)\n",
		       uwg_bbr_effective_cwnd(b), uwg_bbr_cwnd(b));
		kfree(b);
		return -EINVAL;
	}

	/* 2 MB/s over 5 ms is 10 KB, above the 5600-byte minimum window. */
	b->pacing_rate = 2000000;
	if (uwg_bbr_effective_cwnd(b) != 10000 ||
	    uwg_bbr_cwnd_allowance(b) != 10000) {
		pr_err("BBR self-test: cwnd floor %llu, expected 10000 (cwnd=%llu)\n",
		       uwg_bbr_effective_cwnd(b), uwg_bbr_cwnd(b));
		kfree(b);
		return -EINVAL;
	}
	b->inflight = 4000;
	if (uwg_bbr_cwnd_allowance(b) != 6000) {
		pr_err("BBR self-test: floor allowance %llu, expected 6000\n",
		       uwg_bbr_cwnd_allowance(b));
		kfree(b);
		return -EINVAL;
	}

	/* An extreme rate must not inflate the floor past the cap. */
	b->pacing_rate = UWG_BBR_MAX_RATE;
	if (uwg_bbr_effective_cwnd(b) != UWG_BBR_CWND_FLOOR_MAX) {
		pr_err("BBR self-test: cwnd floor %llu exceeds cap %llu\n",
		       uwg_bbr_effective_cwnd(b), UWG_BBR_CWND_FLOOR_MAX);
		kfree(b);
		return -EINVAL;
	}

	/*
	 * The gate is armed only after STARTUP: while full_bw_reached is
	 * false a saturated window must not stop the sender, after the
	 * transition the very same state is a hard stop for the batch.
	 */
	uwg_bbr_init(b, 1400, 20000);
	if (uwg_bbr_full_bw_reached(b)) {
		pr_err("BBR self-test: gate armed during STARTUP\n");
		kfree(b);
		return -EINVAL;
	}
	b->inflight = uwg_bbr_effective_cwnd(b);
	if (uwg_bbr_cwnd_allowance(b)) {
		pr_err("BBR self-test: saturated STARTUP window admits %llu\n",
		       uwg_bbr_cwnd_allowance(b));
		kfree(b);
		return -EINVAL;
	}
	b->full_bw_reached = true;
	if (!uwg_bbr_full_bw_reached(b) || uwg_bbr_cwnd_allowance(b)) {
		pr_err("BBR self-test: gate state lost after STARTUP (reached=%d allowance=%llu)\n",
		       uwg_bbr_full_bw_reached(b), uwg_bbr_cwnd_allowance(b));
		kfree(b);
		return -EINVAL;
	}

	/*
	 * The gate additionally needs a loss-established bound: a fresh
	 * controller keeps inflight_hi at U64_MAX, a loss cut lowers it below
	 * the window, and a later growth of the bound releases it again.
	 */
	if (uwg_bbr_loss_limited(b)) {
		pr_err("BBR self-test: clean controller reports loss-limited (hi=%llu cwnd=%llu)\n",
		       b->inflight_hi, b->cwnd);
		kfree(b);
		return -EINVAL;
	}
	b->inflight_hi = b->cwnd - 1400;
	if (!uwg_bbr_loss_limited(b)) {
		pr_err("BBR self-test: cut bound not seen as loss-limited (hi=%llu cwnd=%llu)\n",
		       b->inflight_hi, b->cwnd);
		kfree(b);
		return -EINVAL;
	}
	b->inflight_hi = b->cwnd + 1400;
	if (uwg_bbr_loss_limited(b)) {
		pr_err("BBR self-test: rebuilt bound still loss-limited (hi=%llu cwnd=%llu)\n",
		       b->inflight_hi, b->cwnd);
		kfree(b);
		return -EINVAL;
	}

	/*
	 * A real loss cut (a hole in the ACK bitmap, PROBE_BW so the cut is
	 * applied) must move inflight_hi down to at most the window: that is
	 * the state in which the sender starts withholding.
	 */
	uwg_bbr_init(b, 1400, 20000);
	b->full_bw_reached = true;
	b->mode = UWG_BBR_PROBE_BW;
	uwg_bbr_on_send(b, b->keypair_id, 0, 1400, 1000000);
	uwg_bbr_on_send(b, b->keypair_id, 1, 1400, 1000000);
	uwg_bbr_on_send(b, b->keypair_id, 2, 1400, 1000000);
	uwg_bbr_on_ack(b, b->keypair_id, 2, 0x5, 0, 2000000);
	if (!b->lost_packets || b->inflight_hi == U64_MAX ||
	    b->inflight_hi > b->cwnd) {
		pr_err("BBR self-test: loss cut did not bound the window (lost=%llu hi=%llu cwnd=%llu)\n",
		       b->lost_packets, b->inflight_hi, b->cwnd);
		kfree(b);
		return -EINVAL;
	}

	kfree(b);
	return 0;
}

int uwg_bbr_selftest(void)
{
	int ret;

	ret = uwg_bbr_selftest_edges();
	if (ret < 0)
		return ret;
	ret = uwg_bbr_selftest_cwnd();
	if (ret < 0)
		return ret;
	ret = uwg_bbr_selftest_epoch();
	if (ret < 0)
		return ret;
	ret = uwg_bbr_selftest_path();
	if (ret < 0)
		return ret;
	ret = uwg_bbr_selftest_clean();
	if (ret < 0)
		return ret;
	return uwg_bbr_selftest_burst();
}
