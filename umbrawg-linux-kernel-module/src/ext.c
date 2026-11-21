// SPDX-License-Identifier: GPL-2.0

#include "ext.h"
#include "peer.h"
#include "device.h"
#include "queueing.h"
#include "bbr.h"
#include "fec.h"
#include "fec_data.h"
#include "timers.h"

#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/unaligned.h>

static bool uwg_ext_kind_valid(u8 kind)
{
	return kind == UWG_EXT_KIND_CAPS ||
	       kind == UWG_EXT_KIND_ACK ||
	       kind == UWG_EXT_KIND_FEC_SHARD;
}

bool uwg_ext_detect(const u8 *data, size_t len)
{
	if (len < UWG_EXT_HEADER_LEN)
		return false;
	if (data[0] != UWG_EXT_TAG ||
	    data[1] != UWG_EXT_MAGIC_0 ||
	    data[2] != UWG_EXT_MAGIC_1 ||
	    data[3] != UWG_EXT_MAGIC_2 ||
	    data[4] != UWG_EXT_VERSION)
		return false;
	return uwg_ext_kind_valid(data[5]);
}

int uwg_ext_parse_header(const u8 *data, size_t len,
			 struct uwg_ext_header *header)
{
	u16 payload_len;

	if (!uwg_ext_detect(data, len))
		return -ENOENT;

	payload_len = get_unaligned_le16(data + 6);
	if ((size_t)payload_len > len - UWG_EXT_HEADER_LEN)
		return -EMSGSIZE;

	header->kind = data[5];
	header->payload_len = payload_len;
	header->payload = data + UWG_EXT_HEADER_LEN;
	return 0;
}

int uwg_ext_parse_caps(const u8 *payload, size_t len,
		       struct uwg_ext_caps *caps)
{
	if (len != UWG_EXT_CAPS_LEN)
		return -EINVAL;

	caps->flags = get_unaligned_le32(payload);
	caps->ack_interval = get_unaligned_le16(payload + 4);
	caps->fec_k = payload[6];
	caps->fec_m = payload[7];
	caps->reserved = get_unaligned_le32(payload + 8);
	return 0;
}

int uwg_ext_parse_ack(const u8 *payload, size_t len, struct uwg_ext_ack *ack)
{
	u8 bitmap_len;

	if (len < UWG_EXT_ACK_HEADER_LEN + 1)
		return -EINVAL;

	bitmap_len = payload[13];
	/* PROTOCOL-EXT allows a 1..8 byte bitmap and Rust accepts it. A short
	 * bitmap must not be zero-extended into holes: the uncovered counters
	 * are simply not reported by this ACK, not lost. Keep the declared
	 * length here and turn the uncovered tail into "already covered" when
	 * the bitmap is consumed (uwg_ext_ack_bitmap()).
	 */
	if (bitmap_len < 1 || bitmap_len > UWG_EXT_ACK_BITMAP_MAX)
		return -EINVAL;
	if (len != UWG_EXT_ACK_HEADER_LEN + bitmap_len)
		return -EINVAL;

	ack->largest = get_unaligned_le64(payload);
	ack->ack_delay_us = get_unaligned_le32(payload + 8);
	ack->flags = payload[12];
	ack->bitmap_len = bitmap_len;
	ack->reserved = get_unaligned_le16(payload + 14);
	memset(ack->bitmap, 0, sizeof(ack->bitmap));
	memcpy(ack->bitmap, payload + UWG_EXT_ACK_HEADER_LEN, bitmap_len);
	return 0;
}

/* Full 64 bit view of an ACK bitmap. Bits the sender did not include are
 * marked set ("covered") so that consumers such as the BBR ring do not count
 * them as holes. Bits inside the declared length keep their wire value.
 */
u64 uwg_ext_ack_bitmap(const struct uwg_ext_ack *ack)
{
	u64 bitmap = get_unaligned_le64(ack->bitmap);
	unsigned int covered = (unsigned int)ack->bitmap_len * 8;

	if (covered < UWG_EXT_ACK_BITMAP_BITS)
		bitmap |= ~0ULL << covered;
	return bitmap;
}

/* Regression check for the short-bitmap compatibility path: uncovered bits
 * must look "not reported" rather than holes, otherwise a one-byte bitmap
 * inflates the loss estimate by up to 63 counters.
 */
bool uwg_ext_ack_selftest(void)
{
	u8 payload[UWG_EXT_ACK_HEADER_LEN + UWG_EXT_ACK_BITMAP_MAX + 1];
	struct uwg_ext_ack ack;
	unsigned int bit, zeros;
	u64 bitmap;
	bool ok = true;

	memset(payload, 0, sizeof(payload));
	put_unaligned_le64(100, payload);
	payload[13] = 1;
	payload[16] = 0x01;
	if (uwg_ext_parse_ack(payload, UWG_EXT_ACK_HEADER_LEN + 1, &ack)) {
		ok = false;
	} else {
		bitmap = uwg_ext_ack_bitmap(&ack);
		if (!(bitmap & 1) || ack.bitmap_len != 1)
			ok = false;
		/* Only the first byte is covered; every bit from 8 upwards
		 * must be masked as "not reported", never as a hole.
		 */
		for (bit = 8; bit < UWG_EXT_ACK_BITMAP_BITS; bit++)
			if (!(bitmap & ((u64)1 << bit)))
				ok = false;
		zeros = 0;
		for (bit = 1; bit < 8; bit++)
			if (!(bitmap & ((u64)1 << bit)))
				++zeros;
		if (zeros != 7)
			ok = false;
	}

	/* Two covered bytes: bits 1..15 are real holes, bits 16..63 are not
	 * covered and must be masked off as "set".
	 */
	memset(payload, 0, sizeof(payload));
	put_unaligned_le64(100, payload);
	payload[13] = 2;
	payload[16] = 0x01;
	if (uwg_ext_parse_ack(payload, UWG_EXT_ACK_HEADER_LEN + 2, &ack)) {
		ok = false;
	} else {
		bitmap = uwg_ext_ack_bitmap(&ack);
		zeros = 0;
		for (bit = 1; bit < 2 * 8; bit++)
			if (!(bitmap & ((u64)1 << bit)))
				++zeros;
		if (zeros != 15)
			ok = false;
		for (bit = 2 * 8; bit < UWG_EXT_ACK_BITMAP_BITS; bit++)
			if (!(bitmap & ((u64)1 << bit)))
				ok = false;
	}

	/* Out of range lengths are still rejected. */
	payload[13] = 0;
	if (uwg_ext_parse_ack(payload, UWG_EXT_ACK_HEADER_LEN, &ack) != -EINVAL)
		ok = false;
	payload[13] = UWG_EXT_ACK_BITMAP_MAX + 1;
	if (uwg_ext_parse_ack(payload, UWG_EXT_ACK_HEADER_LEN +
				       UWG_EXT_ACK_BITMAP_MAX + 1,
			      &ack) != -EINVAL)
		ok = false;
	payload[13] = UWG_EXT_ACK_BITMAP_MAX;
	if (uwg_ext_parse_ack(payload, UWG_EXT_ACK_HEADER_LEN + 1,
			      &ack) != -EINVAL)
		ok = false;

	if (!ok)
		pr_err("EXT ACK self-test: FAIL\n");
	return ok;
}

int uwg_ext_parse_fec_shard(const u8 *payload, size_t len,
			    struct uwg_ext_fec_shard *shard)
{
	u16 total;
	bool parity;

	if (len < UWG_EXT_FEC_HEADER_LEN)
		return -EINVAL;

	shard->block_id = get_unaligned_le32(payload);
	shard->index = payload[4];
	shard->k = payload[5];
	shard->m = payload[6];
	shard->flags = payload[7];
	shard->shard_len = get_unaligned_le16(payload + 8);
	shard->reserved = get_unaligned_le16(payload + 10);

	if (!shard->k || shard->k > UWG_FEC_MAX_DATA ||
	    shard->m > UWG_FEC_MAX_PARITY)
		return -EINVAL;
	total = (u16)shard->k + shard->m;
	if (total > UWG_FEC_MAX_SHARDS)
		return -EINVAL;
	if (shard->index >= total)
		return -EINVAL;

	parity = (shard->flags & UWG_EXT_FEC_FLAG_PARITY) != 0;
	if (parity != (shard->index >= shard->k))
		return -EINVAL;
	if (shard->shard_len != len - UWG_EXT_FEC_HEADER_LEN)
		return -EINVAL;

	shard->payload = payload + UWG_EXT_FEC_HEADER_LEN;
	return 0;
}

void uwg_ext_local_caps(const struct uwg_device *uwg,
			struct uwg_ext_caps *caps)
{
	u32 flags = 0;
	u8 k = 0, m = 0;
	bool adaptive = false;

	memset(caps, 0, sizeof(*caps));
	caps->ack_interval = UWG_EXT_DEFAULT_ACK_INTERVAL;

	if (uwg->bbr_mode != UWG_BBR_MODE_OFF ||
	    uwg->fec_mode != UWG_FEC_MODE_OFF)
		flags |= UWG_EXT_CAP_ACK;

	if (uwg->fec_mode != UWG_FEC_MODE_OFF &&
	    uwg_fec_mode_config(uwg->fec_mode, &k, &m, &adaptive)) {
		flags |= UWG_EXT_CAP_FEC;
		if (adaptive)
			flags |= UWG_EXT_CAP_FEC_ADAPTIVE;
		caps->fec_k = k;
		caps->fec_m = m;
	}

	caps->flags = flags;
}

void uwg_ext_peer_init(struct uwg_peer *peer)
{
	memset(&peer->caps, 0, sizeof(peer->caps));
	memset(&peer->ack_tracker, 0, sizeof(peer->ack_tracker));
	memset(&peer->ack_state, 0, sizeof(peer->ack_state));
	spin_lock_init(&peer->caps.lock);
	spin_lock_init(&peer->ack_state.lock);
	uwg_ext_local_caps(peer->device, &peer->caps.local);
}

bool uwg_ext_enabled(const struct uwg_device *uwg)
{
	return READ_ONCE(uwg->bbr_mode) != UWG_BBR_MODE_OFF ||
	       READ_ONCE(uwg->fec_mode) != UWG_FEC_MODE_OFF;
}

static void uwg_ext_write_header(u8 *buf, u8 kind, u16 payload_len)
{
	buf[0] = UWG_EXT_TAG;
	buf[1] = UWG_EXT_MAGIC_0;
	buf[2] = UWG_EXT_MAGIC_1;
	buf[3] = UWG_EXT_MAGIC_2;
	buf[4] = UWG_EXT_VERSION;
	buf[5] = kind;
	put_unaligned_le16(payload_len, buf + 6);
}

int uwg_ext_build_caps(u8 *buf, size_t len, const struct uwg_ext_caps *caps)
{
	size_t total = UWG_EXT_HEADER_LEN + UWG_EXT_CAPS_LEN;

	if (len < total)
		return -EMSGSIZE;

	uwg_ext_write_header(buf, UWG_EXT_KIND_CAPS, UWG_EXT_CAPS_LEN);
	put_unaligned_le32(caps->flags, buf + 8);
	put_unaligned_le16(caps->ack_interval, buf + 12);
	buf[14] = caps->fec_k;
	buf[15] = caps->fec_m;
	put_unaligned_le32(caps->reserved, buf + 16);
	return (int)total;
}

int uwg_ext_build_ack(u8 *buf, size_t len, const struct uwg_ext_ack *ack)
{
	u8 bitmap_len = ack->bitmap_len;
	size_t total;

	if (!bitmap_len || bitmap_len > UWG_EXT_ACK_BITMAP_MAX)
		bitmap_len = UWG_EXT_ACK_BITMAP_MAX;

	total = UWG_EXT_HEADER_LEN + UWG_EXT_ACK_HEADER_LEN + bitmap_len;
	if (len < total)
		return -EMSGSIZE;

	uwg_ext_write_header(buf, UWG_EXT_KIND_ACK,
			     UWG_EXT_ACK_HEADER_LEN + bitmap_len);
	put_unaligned_le64(ack->largest, buf + 8);
	put_unaligned_le32(ack->ack_delay_us, buf + 16);
	buf[20] = ack->flags;
	buf[21] = bitmap_len;
	put_unaligned_le16(ack->reserved, buf + 22);
	memcpy(buf + 24, ack->bitmap, bitmap_len);
	return (int)total;
}

int uwg_ext_build_fec_shard_header(u8 *buf, size_t len,
				   const struct uwg_ext_fec_shard *shard)
{
	unsigned int total = (unsigned int)shard->k + shard->m;

	if (len < UWG_EXT_HEADER_LEN + UWG_EXT_FEC_HEADER_LEN)
		return -EMSGSIZE;
	if (!shard->k || total > UWG_FEC_MAX_SHARDS ||
	    shard->index >= total)
		return -EINVAL;
	if ((unsigned int)shard->shard_len +
		    UWG_EXT_FEC_HEADER_LEN > 0xffffU)
		return -EMSGSIZE;
	if (!!(shard->flags & UWG_EXT_FEC_FLAG_PARITY) !=
	    (shard->index >= shard->k))
		return -EINVAL;

	uwg_ext_write_header(buf, UWG_EXT_KIND_FEC_SHARD,
			     UWG_EXT_FEC_HEADER_LEN + shard->shard_len);
	put_unaligned_le32(shard->block_id, buf + 8);
	buf[12] = shard->index;
	buf[13] = shard->k;
	buf[14] = shard->m;
	buf[15] = shard->flags;
	put_unaligned_le16(shard->shard_len, buf + 16);
	put_unaligned_le16(shard->reserved, buf + 18);
	return UWG_EXT_HEADER_LEN + UWG_EXT_FEC_HEADER_LEN;
}

void uwg_ext_caps_changed(struct uwg_device *uwg)
{
	struct uwg_peer *peer;

	list_for_each_entry(peer, &uwg->peer_list, peer_list) {
		spin_lock_bh(&peer->caps.lock);
		peer->caps.resend = true;
		peer->caps.send_attempts = 0;
		peer->caps.reply_attempts = 0;
		peer->caps.next_send = 0;
		peer->caps.last_sent = 0;
		spin_unlock_bh(&peer->caps.lock);
		uwg_ext_maybe_send_caps(peer);
	}
}

/* A new session key is a fresh negotiation epoch. CAPS frames sent under the
 * previous keypair may have been dropped by the peer (it installs the new
 * keypair only when it completes the handshake), so a spent attempt budget
 * must not be allowed to keep the exchange silent after a rekey. This is the
 * kernel counterpart of the userspace device re-arming CAPS on the same
 * event.
 */
void uwg_ext_caps_keypair_changed(struct uwg_peer *peer)
{
	spin_lock_bh(&peer->caps.lock);
	peer->caps.resend = true;
	peer->caps.send_attempts = 0;
	peer->caps.reply_attempts = 0;
	peer->caps.next_send = 0;
	peer->caps.last_sent = 0;
	spin_unlock_bh(&peer->caps.lock);
}

/* True when the decrypted packet starts with a well-formed extension header
 * that proves the peer still runs the extension. CAPS is deliberately
 * excluded: two devices that both switched the extension off exchange a
 * single zero CAPS to retract their stale advertisement, and if that frame
 * itself counted as "extension traffic" they would answer each other forever.
 * ACK and FEC_SHARD mean the peer's data plane is still active and a revoke
 * is worthwhile.
 */
bool uwg_ext_peer_extension(const struct sk_buff *skb)
{
	u8 buf[UWG_EXT_HEADER_LEN];
	const u8 *hdr = skb_header_pointer(skb, 0, sizeof(buf), buf);

	return hdr && uwg_ext_detect(hdr, sizeof(buf)) &&
	       hdr[5] != UWG_EXT_KIND_CAPS;
}

void uwg_ext_caps_extension_seen(struct uwg_peer *peer)
{
	spin_lock_bh(&peer->caps.lock);
	peer->caps.extension_seen = true;
	spin_unlock_bh(&peer->caps.lock);
}

/* Schedule a deferred CAPS answer on the existing delayed-ACK timer. A
 * separate timer per peer would need a new teardown path; timer_send_ack is
 * already initialised/shut down with the peer, and uwg_ext_ack_timeout()
 * calls uwg_ext_maybe_send_caps() before its own early returns.
 */
static void uwg_ext_caps_arm(struct uwg_peer *peer)
{
	ktime_t next;
	unsigned long expires;
	s64 ms;
	bool pending;

	spin_lock_bh(&peer->caps.lock);
	pending = peer->caps.resend && peer->caps.next_send != 0;
	next = peer->caps.next_send;
	spin_unlock_bh(&peer->caps.lock);
	if (!pending)
		return;
	ms = ktime_ms_delta(next, ktime_get());
	if (ms <= 0)
		expires = jiffies + 1;
	else
		expires = jiffies + max_t(unsigned long, 1,
					 msecs_to_jiffies((unsigned long)ms));
	uwg_timers_ack_reduce(peer, expires);
}

void uwg_ext_maybe_send_caps(struct uwg_peer *peer)
{
	struct uwg_ext_caps local;
	u8 frame[UWG_EXT_MAX_FRAME_LEN];
	ktime_t now;
	bool revoke;
	int len;

	now = ktime_get();
	spin_lock_bh(&peer->caps.lock);
	uwg_ext_local_caps(peer->device, &peer->caps.local);
	/* With FEC and BBR both off there is nothing to advertise, but a peer
	 * that still believes we run FEC keeps sending shards we no longer
	 * parse. A zero CAPS retracts that stale advertisement: right away when
	 * the local profile is switched off, and again while the peer actually
	 * shows extension traffic. A silent tunnel therefore stays silent.
	 */
	revoke = !peer->caps.local.flags &&
		 (peer->caps.extension_seen ||
		  (peer->caps.resend && peer->caps.peer_valid &&
		   (peer->caps.peer.flags & UWG_EXT_CAP_FEC)));
	if ((!revoke && !peer->caps.local.flags) ||
	    (!revoke && peer->caps.peer_valid && !peer->caps.resend) ||
	    (!revoke &&
	     peer->caps.send_attempts >= UWG_EXT_CAPS_MAX_ATTEMPTS) ||
	    (peer->caps.resend &&
	     ktime_before(now, peer->caps.next_send))) {
		spin_unlock_bh(&peer->caps.lock);
		return;
	}
	if (peer->caps.send_attempts < UWG_EXT_CAPS_MAX_ATTEMPTS)
		++peer->caps.send_attempts;
	peer->caps.resend = false;
	peer->caps.extension_seen = false;
	/* The very first CAPS frame races with the peer installing the new
	 * keypair and can be lost. Retry quickly at first, then back off.
	 */
	peer->caps.next_send = ktime_add_ms(
		now, revoke ||
		peer->caps.send_attempts >= UWG_EXT_CAPS_MAX_ATTEMPTS ?
			     UWG_EXT_CAPS_RETRY_MS : UWG_EXT_CAPS_FAST_RETRY_MS);
	local = peer->caps.local;
	spin_unlock_bh(&peer->caps.lock);

	len = uwg_ext_build_caps(frame, sizeof(frame), &local);
	if (likely(len > 0 &&
		   !uwg_packet_send_control(peer, frame, (size_t)len))) {
		spin_lock_bh(&peer->caps.lock);
		peer->caps.last_sent = now;
		spin_unlock_bh(&peer->caps.lock);
		return;
	}

	spin_lock_bh(&peer->caps.lock);
	if (peer->caps.send_attempts)
		--peer->caps.send_attempts;
	peer->caps.resend = true;
	peer->caps.next_send = 0;
	spin_unlock_bh(&peer->caps.lock);
	net_dbg_ratelimited("%s: Could not send CAPS to peer %llu\n",
			    peer->device->dev->name, peer->internal_id);
}

static void uwg_ext_ack_observe(struct uwg_peer_ack_state *state, u64 keypair_id,
				u64 nonce, ktime_t now, bool count_for_ack)
{
	u64 shift;

	if (!state->valid || state->keypair_id != keypair_id) {
		state->keypair_id = keypair_id;
		state->largest = nonce;
		state->bitmap = 1;
		state->largest_ktime = now;
		state->valid = true;
	} else if (nonce > state->largest) {
		shift = nonce - state->largest;
		state->bitmap = shift >= UWG_EXT_ACK_BITMAP_BITS ?
					1 : (state->bitmap << shift) | 1;
		state->largest = nonce;
		state->largest_ktime = now;
	} else {
		shift = state->largest - nonce;
		if (shift < UWG_EXT_ACK_BITMAP_BITS)
			state->bitmap |= (u64)1 << shift;
	}
	if (count_for_ack) {
		/* A new ACK cycle: draw both the packet threshold and the
		 * delayed-ACK deadline, so neither the count nor the timing
		 * is predictable.
		 */
		if (!state->pending) {
			state->ack_target = get_random_u32_inclusive(
				UWG_EXT_ACK_INTERVAL_MIN,
				UWG_EXT_ACK_INTERVAL_MAX);
			state->ack_deadline = jiffies + max_t(unsigned long, 1,
				usecs_to_jiffies(get_random_u32_inclusive(
					UWG_EXT_ACK_DELAY_MIN_US,
					UWG_EXT_ACK_DELAY_MAX_US)));
		}
		++state->pending;
	}
}

static int uwg_ext_ack_build(const struct uwg_peer_ack_state *state,
			     ktime_t now, u8 *frame, size_t len)
{
	struct uwg_ext_ack ack;
	u64 delay_us;

	memset(&ack, 0, sizeof(ack));
	ack.largest = state->largest;
	delay_us = (u64)ktime_to_us(ktime_sub(now, state->largest_ktime));
	ack.ack_delay_us = (u32)min_t(u64, delay_us, U32_MAX);
	ack.bitmap_len = UWG_EXT_ACK_BITMAP_MAX;
	put_unaligned_le64(state->bitmap, ack.bitmap);
	return uwg_ext_build_ack(frame, len, &ack);
}

static bool uwg_ext_ack_due(const struct uwg_peer_ack_state *state)
{
	if (!state->pending)
		return false;
	return state->pending >= state->ack_target ||
	       time_after_eq(jiffies, state->ack_deadline);
}

static bool uwg_ext_peer_answers(const struct uwg_peer *peer)
{
	return READ_ONCE(peer->caps.peer_valid) ||
	       READ_ONCE(peer->caps.send_attempts) < UWG_EXT_CAPS_MAX_ATTEMPTS;
}

static void uwg_ext_ack_armed(struct uwg_peer *peer)
{
	unsigned long deadline;

	/* Nothing to acknowledge: stay silent and do not burn a timer. */
	if (!READ_ONCE(peer->ack_state.pending))
		return;

	deadline = READ_ONCE(peer->ack_state.ack_deadline);
	if (time_before(deadline, jiffies + 1))
		deadline = jiffies + 1;
	/* Never touch the timer directly here: this runs from the NAPI poll,
	 * which can overlap peer teardown. The helper repeats the is_dead/
	 * netif_running check under rcu_read_lock_bh().
	 */
	uwg_timers_ack_reduce(peer, deadline);
}

void uwg_ext_data_received(struct uwg_peer *peer, u64 keypair_id, u64 nonce,
			   bool count_for_ack)
{
	struct uwg_peer_ack_state *state = &peer->ack_state;
	struct noise_keypair *keypair;
	u8 frame[UWG_EXT_MAX_FRAME_LEN];
	ktime_t now;
	int len = -ENOENT;

	if (!uwg_ext_enabled(peer->device))
		return;
	if (!uwg_ext_peer_answers(peer))
		return;

	rcu_read_lock_bh();
	keypair = rcu_dereference_bh(peer->keypairs.current_keypair);
	if (unlikely(!keypair || keypair->internal_id != keypair_id)) {
		rcu_read_unlock_bh();
		return;
	}
	rcu_read_unlock_bh();

	now = ktime_get();
	spin_lock_bh(&state->lock);
	uwg_ext_ack_observe(state, keypair_id, nonce, now, count_for_ack);
	if (uwg_ext_ack_due(state)) {
		len = uwg_ext_ack_build(state, now, frame, sizeof(frame));
		state->pending = 0;
	}
	spin_unlock_bh(&state->lock);

	if (likely(len > 0)) {
		if (unlikely(uwg_packet_send_control(peer, frame, (size_t)len)))
			net_dbg_ratelimited("%s: Could not send ACK to peer %llu\n",
					    peer->device->dev->name,
					    peer->internal_id);
		return;
	}
	uwg_ext_ack_armed(peer);
}

void uwg_ext_ack_timeout(struct uwg_peer *peer)
{
	struct uwg_peer_ack_state *state = &peer->ack_state;
	u8 frame[UWG_EXT_MAX_FRAME_LEN];
	ktime_t now;
	bool again = false;
	int len = -ENOENT;

	/* The delayed-ACK timer doubles as the CAPS deferral timer: a changed
	 * peer profile that arrived less than UWG_EXT_CAPS_CHANGED_MIN_MS
	 * after our last CAPS must still be answered, not dropped.
	 */
	uwg_ext_maybe_send_caps(peer);
	if (!uwg_ext_enabled(peer->device))
		return;
	if (!uwg_ext_peer_answers(peer))
		return;

	now = ktime_get();
	spin_lock_bh(&state->lock);
	if (state->valid && state->pending) {
		if (time_after_eq(jiffies, state->ack_deadline)) {
			len = uwg_ext_ack_build(state, now, frame,
						sizeof(frame));
			state->pending = 0;
		} else {
			again = true;
		}
	}
	spin_unlock_bh(&state->lock);

	if (len > 0) {
		uwg_packet_send_control(peer, frame, (size_t)len);
	} else if (again) {
		uwg_ext_ack_armed(peer);
	}
	/* The ACK path may have reduced the timer to an earlier deadline; make
	 * sure an overdue-but-still-deferred CAPS answer is not forgotten.
	 */
	uwg_ext_caps_arm(peer);
}

static bool uwg_ext_caps_same(const struct uwg_ext_caps *a,
			      const struct uwg_ext_caps *b)
{
	return a->flags == b->flags &&
	       a->ack_interval == b->ack_interval &&
	       a->fec_k == b->fec_k &&
	       a->fec_m == b->fec_m;
}

/*
 * The data plane only implements k <= 8 and m <= 2. A peer advertising a
 * bigger block is not an error - it must simply never be matched, otherwise
 * both sides would send a profile the other one drops.
 */
static void uwg_ext_sanitize_caps(struct uwg_peer *peer,
				  struct uwg_ext_caps *caps)
{
	if (!(caps->flags & UWG_EXT_CAP_FEC) ||
	    (caps->fec_k >= 1 && caps->fec_k <= UWG_FEC_DATA_MAX_K &&
	     caps->fec_m >= 1 && caps->fec_m <= UWG_FEC_DATA_MAX_M))
		return;

	net_dbg_ratelimited("%s: Peer %llu advertised unsupported FEC %u:%u\n",
			    peer->device->dev->name, peer->internal_id,
			    caps->fec_k, caps->fec_m);
	caps->flags &= ~(UWG_EXT_CAP_FEC | UWG_EXT_CAP_FEC_ADAPTIVE);
	caps->fec_k = 0;
	caps->fec_m = 0;
}

static void uwg_ext_handle_caps(struct uwg_peer *peer, const u8 *payload,
				size_t len)
{
	struct uwg_ext_caps caps;
	ktime_t now;
	bool changed;
	bool too_soon;
	bool defer = false;
	bool send = false;

	if (uwg_ext_parse_caps(payload, len, &caps))
		return;
	uwg_ext_sanitize_caps(peer, &caps);
	now = ktime_get();
	spin_lock_bh(&peer->caps.lock);
	uwg_ext_local_caps(peer->device, &peer->caps.local);
	changed = !peer->caps.last_peer_valid ||
		  !uwg_ext_caps_same(&peer->caps.last_peer, &caps);
	peer->caps.last_peer = caps;
	peer->caps.last_peer_valid = true;
	peer->caps.peer = caps;
	peer->caps.peer_valid = true;
	if (changed)
		peer->caps.reply_attempts = 0;
	/* Our own CAPS frame may have been sent before the peer installed the
	 * new keypair and was lost. Hearing a new profile from the peer is a
	 * good moment to (re)send ours.
	 * send_attempts == 0 means we have not managed to send CAPS at all.
	 *
	 * Our advertisement only depends on the local profile, so a peer that
	 * keeps changing its CAPS does not need an answer per change: one
	 * frame sent less than UWG_EXT_CAPS_CHANGED_MIN_MS ago carries the
	 * same information. Skipping the duplicate keeps a hostile or flapping
	 * peer from turning this into a control-frame amplifier; the bounded
	 * answer to an identical repeat (the peer retries every 250 ms)
	 * still converges the exchange if the earlier frame was lost.
	 */
	too_soon = peer->caps.last_sent &&
		   ktime_before(now, ktime_add_ms(peer->caps.last_sent,
						  UWG_EXT_CAPS_CHANGED_MIN_MS));
	if (changed) {
		if (too_soon) {
			/* Do not drop the answer: the recent CAPS may have
			 * been lost. Answer as soon as the minimum spacing
			 * allows, via the delayed-ACK timer.
			 */
			peer->caps.resend = true;
			peer->caps.next_send = ktime_add_ms(
				peer->caps.last_sent,
				UWG_EXT_CAPS_CHANGED_MIN_MS);
			if (peer->caps.send_attempts >=
			    UWG_EXT_CAPS_MAX_ATTEMPTS)
				peer->caps.send_attempts =
					UWG_EXT_CAPS_MAX_ATTEMPTS - 1;
			defer = true;
		} else {
			peer->caps.resend = true;
			peer->caps.next_send = 0;
			send = true;
		}
	} else if (!too_soon) {
		if (!peer->caps.send_attempts) {
			peer->caps.resend = true;
			peer->caps.next_send = 0;
			send = true;
		} else if (peer->caps.reply_attempts <
			   UWG_EXT_CAPS_MAX_REPLIES) {
			/* An identical repeat is not necessarily our own frame
			 * echoed back: a re-created peer has no memory of the
			 * CAPS we sent it, and if our earlier frame was lost it
			 * would keep dropping every shard as dropped_disabled
			 * forever. Answer a bounded number of repeats per
			 * received profile so the exchange always converges,
			 * while two kernels still cannot answer each other
			 * indefinitely.
			 */
			++peer->caps.reply_attempts;
			peer->caps.resend = true;
			peer->caps.next_send = 0;
			send = true;
		}
	}
	if (send && peer->caps.send_attempts >= UWG_EXT_CAPS_MAX_ATTEMPTS)
		peer->caps.send_attempts = UWG_EXT_CAPS_MAX_ATTEMPTS - 1;
	spin_unlock_bh(&peer->caps.lock);
	if (send)
		uwg_ext_maybe_send_caps(peer);
	else if (defer)
		uwg_ext_caps_arm(peer);
}

static void uwg_ext_bbr_on_ack(struct uwg_peer *peer, u64 keypair_id,
			       u64 largest, u64 bitmap, u32 ack_delay_us)
{
	struct uwg_bbr *bbr;

	if (READ_ONCE(peer->device->bbr_mode) == UWG_BBR_MODE_OFF)
		return;

	rcu_read_lock();
	bbr = uwg_peer_bbr_lookup(peer);
	if (bbr) {
		spin_lock_bh(&peer->bbr_lock);
		uwg_bbr_on_ack(bbr, keypair_id, largest, bitmap, ack_delay_us,
			       ktime_get_ns());
		spin_unlock_bh(&peer->bbr_lock);
	}
	rcu_read_unlock();

	/* The ACK just released inflight, so whatever the cwnd gate parked can
	 * go now. This is the RX/NAPI path: uwg_ext_receive() runs from
	 * uwg_packet_consume_data_done(), which already calls
	 * uwg_packet_send_staged_packets() in the same context, so no
	 * workqueue is needed here. The function never sleeps -- it moves skbs
	 * between queue heads and hands them to the crypto workqueue -- and all
	 * its locks are bh-safe.
	 */
	if (READ_ONCE(peer->device->bbr_mode) == UWG_BBR_MODE_ON &&
	    !skb_queue_empty_lockless(&peer->staged_packet_queue))
		uwg_packet_send_staged_packets(peer);
}

static void uwg_ext_handle_ack(struct uwg_peer *peer, u64 keypair_id,
			       const u8 *payload, size_t len)
{
	struct uwg_ext_ack ack;
	u64 bitmap;

	if (uwg_ext_parse_ack(payload, len, &ack))
		return;

	bitmap = uwg_ext_ack_bitmap(&ack);
	peer->ack_tracker.largest = ack.largest;
	peer->ack_tracker.bitmap = bitmap;
	peer->ack_tracker.ack_delay_us = ack.ack_delay_us;
	peer->ack_tracker.bitmap_len = ack.bitmap_len;
	peer->ack_tracker.flags = ack.flags;
	peer->ack_tracker.valid = true;
	peer->ack_tracker.received++;
	peer->ack_tracker.last_ack_jiffies = jiffies;
	peer->ack_tracker.last_ack_ktime = ktime_get();

	uwg_ext_bbr_on_ack(peer, keypair_id, ack.largest, bitmap,
			   ack.ack_delay_us);
}

static enum uwg_ext_rx_result uwg_ext_handle_fec_shard(struct uwg_peer *peer,
						       struct sk_buff *skb,
						       const u8 *payload,
						       size_t len)
{
	struct uwg_ext_fec_shard shard;
	u64 keypair_id;
	int ret;

	if (uwg_ext_parse_fec_shard(payload, len, &shard))
		return UWG_EXT_RX_INVALID;
	if (unlikely(!PACKET_CB(skb)->keypair))
		return UWG_EXT_RX_INVALID;
	keypair_id = PACKET_CB(skb)->keypair->internal_id;
	ret = uwg_fec_rx_shard(peer, &shard, skb,
			       UWG_EXT_HEADER_LEN + UWG_EXT_FEC_HEADER_LEN,
			       keypair_id, true);
	if (ret)
		return UWG_EXT_RX_INVALID;
	/* A shard is a real transport packet, so it keeps the data path alive
	 * just like a plain packet: without this an FEC-only flow (all inner
	 * traffic already turned into shards) would never arm the keepalive
	 * timer and the tunnel could be torn down while it is busy.
	 */
	uwg_timers_data_received(peer);
	return UWG_EXT_RX_CONSUMED;
}

enum uwg_ext_rx_result uwg_ext_receive(struct uwg_peer *peer,
				       struct sk_buff *skb)
{
	u8 hdrbuf[UWG_EXT_HEADER_LEN];
	u8 capsbuf[UWG_EXT_CAPS_LEN];
	u8 ackbuf[UWG_EXT_ACK_HEADER_LEN + UWG_EXT_ACK_BITMAP_MAX];
	u8 fecbuf[UWG_EXT_FEC_HEADER_LEN];
	const u8 *hdr;
	struct uwg_ext_header header;
	u64 keypair_id = 0;

	if (skb->len < UWG_EXT_HEADER_LEN)
		return UWG_EXT_RX_NOT_EXTENSION;

	hdr = skb_header_pointer(skb, 0, sizeof(hdrbuf), hdrbuf);
	if (!hdr || !uwg_ext_detect(hdr, sizeof(hdrbuf)))
		return UWG_EXT_RX_NOT_EXTENSION;
	if (uwg_ext_parse_header(hdr, skb->len, &header))
		return UWG_EXT_RX_INVALID;

	/* Account every ext frame for BBR/ACK feedback. FEC shards are real
	 * transport packets and must be acknowledged; CAPS/ACK frames update
	 * the bitmap but must not trigger another ACK (no ACK-on-ACK).
	 * An ext frame always arrives after decryption, so the keypair is set;
	 * if it is not, keypair_id stays 0 and the ACK is ignored by BBR
	 * because it cannot be attributed to the current epoch.
	 */
	if (likely(PACKET_CB(skb)->keypair)) {
		keypair_id = PACKET_CB(skb)->keypair->internal_id;
		uwg_ext_data_received(peer, keypair_id, PACKET_CB(skb)->nonce,
				      header.kind == UWG_EXT_KIND_FEC_SHARD);
	}

	switch (header.kind) {
	case UWG_EXT_KIND_CAPS:
		if (header.payload_len != UWG_EXT_CAPS_LEN ||
		    skb_copy_bits(skb, UWG_EXT_HEADER_LEN, capsbuf,
				  UWG_EXT_CAPS_LEN))
			return UWG_EXT_RX_INVALID;
		uwg_ext_handle_caps(peer, capsbuf, UWG_EXT_CAPS_LEN);
		return UWG_EXT_RX_CONSUMED;
	case UWG_EXT_KIND_ACK:
		if (header.payload_len < UWG_EXT_ACK_HEADER_LEN + 1 ||
		    header.payload_len > sizeof(ackbuf) ||
		    skb_copy_bits(skb, UWG_EXT_HEADER_LEN, ackbuf,
				  header.payload_len))
			return UWG_EXT_RX_INVALID;
		uwg_ext_handle_ack(peer, keypair_id, ackbuf,
				   header.payload_len);
		return UWG_EXT_RX_CONSUMED;
	case UWG_EXT_KIND_FEC_SHARD:
		if (header.payload_len < UWG_EXT_FEC_HEADER_LEN ||
		    skb_copy_bits(skb, UWG_EXT_HEADER_LEN, fecbuf,
				  UWG_EXT_FEC_HEADER_LEN))
			return UWG_EXT_RX_INVALID;
		return uwg_ext_handle_fec_shard(peer, skb, fecbuf,
						header.payload_len);
	default:
		return UWG_EXT_RX_INVALID;
	}
}
