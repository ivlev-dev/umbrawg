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
 * 96 KiB per peer. At 1400-byte datagrams this covers 5.7 MiB, i.e. one
 * bandwidth-delay product of a 1 Gbit/s path with a 46 ms RTT or, with the
 * 1.5x FEC overhead, roughly 3.8 MiB of inner traffic. The Rust crate used
 * 8192 records of 32 bytes (256 KiB per peer); 4096 records are allocated
 * on the heap with the rest of struct uwg_bbr and still leave the delivered
 * window below 2^29 (4096 * 65535 bytes).
 */
#define UWG_BBR_RING_CAPACITY 4096

/*
 * Upper bound on the extra delay the token bucket may add to a datagram.
 * Matches UWG_TX_PACE_MAX_NS in send.c: delaying a datagram for longer
 * than this is worse than briefly exceeding cwnd. The congestion window
 * itself is not enforced here any more, see uwg_packet_cwnd_gate().
 */
#define UWG_BBR_DRAIN_DELAY_MAX_NS 2000000ULL

/* Defaults for uwg_bbr_init() when the caller passes zeroes. */
#define UWG_BBR_DEFAULT_MSS 1400
#define UWG_BBR_DEFAULT_RTT_US 20000
#define UWG_BBR_MIN_CWND_PACKETS 4

/*
 * Lower bound on the window the sender is allowed to use, expressed as the
 * amount of data that fits in UWG_BBR_CWND_FLOOR_NS at the current pacing
 * rate.
 *
 * The peer acknowledges in bursts: an ACK covers 8-16 datagrams or arrives
 * after up to 5 ms of delayed-ACK time. On a low-RTT path cwnd (= 2 * BDP)
 * is smaller than one such burst, so an ACK-clocked gate would send the
 * window and then idle until the next ACK -- which is exactly the sleep
 * ceiling cwnd used to impose on short-RTT links. Covering one worst-case
 * ACK interval keeps the gate open at line rate there, while on normal RTTs
 * cwnd is far above the floor and the gate behaves as before.
 *
 * The floor is capped so an extreme pacing rate (or a bogus bandwidth
 * estimate) cannot inflate the window without bound.
 */
#define UWG_BBR_CWND_FLOOR_NS 5000000ULL
#define UWG_BBR_CWND_FLOOR_MAX (4ULL << 20)

enum uwg_bbr_mode {
	UWG_BBR_STARTUP = 0,
	UWG_BBR_PROBE_BW,
	UWG_BBR_PROBE_RTT,
};

enum uwg_bbr_slot_state {
	UWG_BBR_SLOT_EMPTY = 0,
	UWG_BBR_SLOT_INFLIGHT,
	UWG_BBR_SLOT_ACKED,
	UWG_BBR_SLOT_LOST,
	/* Counted as a loss of the current round, bytes still in flight. */
	UWG_BBR_SLOT_LOST_NOTED,
	/* Dropped locally after on_send(): bytes were returned to the caller. */
	UWG_BBR_SLOT_DROPPED,
};

/*
 * One tracked datagram, 24 bytes.
 *
 * The low 29 bits of delivered_state hold the low bits of the global
 * delivered counter at the moment of the send; the top 3 bits hold the
 * slot state. All delivered-length deltas are computed modulo 2^29, which
 * is safe because a record is evicted after at most UWG_BBR_RING_CAPACITY
 * datagrams: 4096 * 65535 bytes is far below 2^29. This keeps the record
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

	/* Keypair generation: counters restart at zero on every rekey. */
	u32 epoch;
	u64 base_counter;
	u64 keypair_id;

	u64 pacing_rate;
	u64 cwnd;
	u64 inflight;
	u64 delivered;
	u64 largest_acked;
	u64 max_sent;
	/* Smallest counter that may still be in flight, for range-limited
	 * release instead of a full ring scan on every ACK.
	 */
	u64 oldest_inflight;
	bool oldest_valid;

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

struct uwg_bbr_snapshot {
	u8 mode;
	u64 cwnd;
	u64 inflight;
	u64 pacing_rate;
	u64 btl_bw;
	u64 min_rtt_ns;
	u64 round_lost;
};

void uwg_bbr_init(struct uwg_bbr *b, u32 mss, u32 initial_rtt_us);
/* Re-derives the loss unit, min_cwnd and pacer burst after the interface MTU
 * changed (FEC lowers it to a single-shard budget). Keeps the measured
 * bandwidth, RTT and the current window, only raising cwnd to the new floor.
 * Caller must hold the peer's bbr_lock.
 */
void uwg_bbr_set_mss(struct uwg_bbr *b, u32 mss);
/* Caller must hold the peer's bbr_lock. */
void uwg_bbr_new_epoch(struct uwg_bbr *b, u64 keypair_id, u64 now_ns);
void uwg_bbr_snapshot_get(const struct uwg_bbr *b,
			  struct uwg_bbr_snapshot *snap);
void uwg_bbr_on_send(struct uwg_bbr *b, u64 keypair_id, u64 counter, u32 len,
		     u64 now_ns);
void uwg_bbr_note_sent(struct uwg_bbr *b, u64 keypair_id, u64 counter);
void uwg_bbr_on_sent(struct uwg_bbr *b, u64 counter, u64 now_ns);
void uwg_bbr_on_ack(struct uwg_bbr *b, u64 keypair_id, u64 largest, u64 bitmap,
		    u32 ack_delay_us, u64 now_ns);
u64 uwg_bbr_next_delay_ns(struct uwg_bbr *b, u32 len, u64 now_ns);
u64 uwg_bbr_pacing_rate(const struct uwg_bbr *b);
u64 uwg_bbr_cwnd(const struct uwg_bbr *b);
u64 uwg_bbr_inflight(const struct uwg_bbr *b);
/* Window the sender may actually use: max(cwnd, floor), where the floor is
 * UWG_BBR_CWND_FLOOR_NS worth of traffic at the pacing rate, capped at
 * UWG_BBR_CWND_FLOOR_MAX. uwg_bbr_cwnd() keeps reporting the raw value.
 * Caller must hold the peer's bbr_lock.
 */
u64 uwg_bbr_effective_cwnd(const struct uwg_bbr *b);
/* True once STARTUP has established the pipe is full. The sender arms the
 * cwnd gate only then: during STARTUP the window tracks the pacer and
 * withholding on it stalls bandwidth discovery instead of shaping it.
 * Caller must hold the peer's bbr_lock.
 */
bool uwg_bbr_full_bw_reached(const struct uwg_bbr *b);
/* True when a loss cut has pushed inflight_hi below the congestion window,
 * i.e. the loss response, not the path, is the binding constraint. On a
 * clean channel inflight_hi starts at U64_MAX and only ever grows, so this
 * stays false. Caller must hold the peer's bbr_lock.
 */
bool uwg_bbr_loss_limited(const struct uwg_bbr *b);
/* Bytes the effective congestion window still admits, zero when it is
 * saturated. Caller must hold the peer's bbr_lock.
 */
u64 uwg_bbr_cwnd_allowance(const struct uwg_bbr *b);
void uwg_bbr_on_loss(struct uwg_bbr *b, u64 counter, u64 now_ns);
void uwg_bbr_on_drop(struct uwg_bbr *b, u64 counter);
int uwg_bbr_selftest(void);

#endif /* _UWG_BBR_H */
