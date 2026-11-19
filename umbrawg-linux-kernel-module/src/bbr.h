/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BBRv3-style congestion controller for UmbraWG.
 *
 * Pure library: it never touches sk_buffs or timers. The caller owns the
 * state, feeds send/ack/loss events and reads the control values back.
 */

#ifndef _UWG_BBR_H
#define _UWG_BBR_H

#include <linux/types.h>

/*
 * Number of tracked datagrams. Each record is 24 bytes, so the ring costs
 * 48 KiB per peer. At 1400-byte datagrams this covers 2.8 MiB, i.e. one
 * bandwidth-delay product of a 1 Gbit/s path with a 22 ms RTT. The Rust
 * crate used 8192 records of 32 bytes (256 KiB per peer), which is too
 * much to keep in struct uwg_peer; 2048 records still cover every path
 * the tunnel targets and evictions are accounted as orphaned packets.
 */
#define UWG_BBR_RING_CAPACITY 2048

/* Defaults for uwg_bbr_init() when the caller passes zeroes. */
#define UWG_BBR_DEFAULT_MSS 1400
#define UWG_BBR_DEFAULT_RTT_US 20000
#define UWG_BBR_MIN_CWND_PACKETS 4

enum uwg_bbr_mode {
	UWG_BBR_STARTUP = 0,
	UWG_BBR_PROBE_BW,
	UWG_BBR_PROBE_RTT,
};

enum uwg_bbr_slot_state {
	UWG_BBR_SLOT_EMPTY = 0,
	UWG_BBR_SLOT_INFLIGHT,
	UWG_BBR_SLOT_RELEASED,
	UWG_BBR_SLOT_ACKED,
	UWG_BBR_SLOT_LOST,
};

/*
 * One tracked datagram, 24 bytes.
 *
 * The low 29 bits of delivered_state hold the low bits of the global
 * delivered counter at the moment of the send; the top 3 bits hold the
 * slot state. All delivered-length deltas are computed modulo 2^29, which
 * is safe because a record is evicted after at most UWG_BBR_RING_CAPACITY
 * datagrams: 2048 * 65535 bytes is far below 2^29. This keeps the record
 * at exactly 24 bytes with no padding.
 */
struct uwg_bbr_sent {
	u64 counter;
	u64 sent_ns;
	u32 len;
	u32 delivered_state;
};

struct uwg_bbr_bw {
	u64 slots[10];
	u32 index;
};

struct uwg_bbr_min_rtt {
	u64 min_ns;
	u64 stamp_ns;
	u64 latest_ns;
	bool seen_min;
	bool seen_latest;
};

struct uwg_bbr_pacer {
	u64 rate;
	u64 burst;
	u64 remainder;
	u64 last_ns;
	u64 mss;
	s64 allowance;
	bool started;
};

struct uwg_bbr {
	u64 mss;
	u64 min_cwnd;
	u64 initial_rtt_ns;
	u64 initial_rate;

	u8 mode;
	u8 cycle_idx;

	u64 pacing_rate;
	u64 cwnd;
	u64 inflight;
	u64 delivered;
	u64 largest_acked;

	struct uwg_bbr_pacer pacer;
	struct uwg_bbr_sent ring[UWG_BBR_RING_CAPACITY];
	struct uwg_bbr_bw bw;
	u64 btl_bw;
	struct uwg_bbr_min_rtt min_rtt;

	u64 full_bw;
	u32 full_bw_cnt;
	bool full_bw_reached;

	u64 round_count;
	u64 next_round_delivered;
	u64 round_delivered;
	u64 round_lost;
	u64 round_max_inflight;
	bool round_congestion;
	u64 last_cut_round;

	bool app_limited;

	u64 inflight_hi;
	u64 inflight_lo;
	u64 bw_hi;

	u64 cycle_start_ns;
	u64 probe_rtt_start_ns;
	u64 probe_rtt_done_ns;
	u64 probe_rtt_round;

	u64 lost_bytes;
	u64 lost_packets;
	u64 spurious_losses;
	u64 orphaned_packets;
};

void uwg_bbr_init(struct uwg_bbr *b, u32 mss, u32 initial_rtt_us);
void uwg_bbr_on_send(struct uwg_bbr *b, u64 counter, u32 len, u64 now_ns);
void uwg_bbr_on_ack(struct uwg_bbr *b, u64 largest, u64 bitmap,
		    u32 ack_delay_us, u64 now_ns);
u64 uwg_bbr_next_delay_ns(struct uwg_bbr *b, u32 len, u64 now_ns);
u64 uwg_bbr_pacing_rate(const struct uwg_bbr *b);
u64 uwg_bbr_cwnd(const struct uwg_bbr *b);
u64 uwg_bbr_inflight(const struct uwg_bbr *b);
void uwg_bbr_on_loss(struct uwg_bbr *b, u64 counter, u64 now_ns);
int uwg_bbr_selftest(void);

#endif /* _UWG_BBR_H */
