// SPDX-License-Identifier: GPL-2.0

#include "ext.h"
#include "peer.h"
#include "device.h"
#include "queueing.h"
#include "bbr.h"
#include "fec.h"
#include "fec_data.h"

#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
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

void uwg_ext_maybe_send_caps(struct uwg_peer *peer)
{
	struct uwg_ext_caps local;
	u8 frame[UWG_EXT_MAX_FRAME_LEN];
	ktime_t now;
	int len;

	if (!uwg_ext_enabled(peer->device))
		return;

	now = ktime_get();
	spin_lock_bh(&peer->caps.lock);
	uwg_ext_local_caps(peer->device, &peer->caps.local);
	if (!peer->caps.local.flags ||
	    (peer->caps.peer_valid && !peer->caps.resend) ||
	    peer->caps.send_attempts >= UWG_EXT_CAPS_MAX_ATTEMPTS ||
	    (peer->caps.send_attempts &&
	     ktime_before(now, peer->caps.next_send))) {
		spin_unlock_bh(&peer->caps.lock);
		return;
	}
	++peer->caps.send_attempts;
	peer->caps.resend = false;
	peer->caps.next_send = ktime_add_ms(now, UWG_EXT_CAPS_RETRY_MS);
	local = peer->caps.local;
	spin_unlock_bh(&peer->caps.lock);

	len = uwg_ext_build_caps(frame, sizeof(frame), &local);
	if (likely(len > 0 &&
		   !uwg_packet_send_control(peer, frame, (size_t)len)))
		return;

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
				u64 nonce, ktime_t now)
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
	++state->pending;
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

static bool uwg_ext_ack_due(const struct uwg_peer_ack_state *state,
			    u32 interval, ktime_t now)
{
	if (!state->pending)
		return false;
	if (!state->sent || state->pending >= interval)
		return true;
	return ktime_after(now, ktime_add_ms(state->last_ack_ktime,
					     UWG_EXT_ACK_MIN_INTERVAL_MS));
}

static bool uwg_ext_peer_answers(const struct uwg_peer *peer)
{
	return READ_ONCE(peer->caps.peer_valid) ||
	       READ_ONCE(peer->caps.send_attempts) < UWG_EXT_CAPS_MAX_ATTEMPTS;
}

static void uwg_ext_ack_armed(struct uwg_peer *peer)
{
	timer_reduce(&peer->timer_send_ack, jiffies + 1);
}

void uwg_ext_data_received(struct uwg_peer *peer, u64 keypair_id, u64 nonce)
{
	struct uwg_peer_ack_state *state = &peer->ack_state;
	struct noise_keypair *keypair;
	u8 frame[UWG_EXT_MAX_FRAME_LEN];
	u32 interval;
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
	interval = READ_ONCE(peer->caps.local.ack_interval);
	if (!interval)
		interval = UWG_EXT_DEFAULT_ACK_INTERVAL;

	spin_lock_bh(&state->lock);
	uwg_ext_ack_observe(state, keypair_id, nonce, now);
	if (uwg_ext_ack_due(state, interval, now)) {
		len = uwg_ext_ack_build(state, now, frame, sizeof(frame));
		state->pending = 0;
		state->sent = true;
		state->last_ack_ktime = now;
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

	if (!uwg_ext_enabled(peer->device))
		return;
	if (!uwg_ext_peer_answers(peer))
		return;

	now = ktime_get();
	spin_lock_bh(&state->lock);
	if (state->valid && state->pending) {
		if (ktime_after(now, ktime_add_ms(state->last_ack_ktime,
						   UWG_EXT_ACK_MIN_INTERVAL_MS))) {
			len = uwg_ext_ack_build(state, now, frame,
						sizeof(frame));
			state->pending = 0;
			state->sent = true;
			state->last_ack_ktime = now;
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
}

static void uwg_ext_handle_caps(struct uwg_peer *peer, const u8 *payload,
				size_t len)
{
	struct uwg_ext_caps caps;

	if (uwg_ext_parse_caps(payload, len, &caps))
		return;
	spin_lock_bh(&peer->caps.lock);
	uwg_ext_local_caps(peer->device, &peer->caps.local);
	peer->caps.peer = caps;
	peer->caps.peer_valid = true;
	spin_unlock_bh(&peer->caps.lock);
}

static void uwg_ext_bbr_on_ack(struct uwg_peer *peer, u64 largest, u64 bitmap,
			       u32 ack_delay_us)
{
	struct uwg_bbr *bbr;

	if (READ_ONCE(peer->device->bbr_mode) == UWG_BBR_MODE_OFF)
		return;

	rcu_read_lock();
	bbr = uwg_peer_bbr_lookup(peer);
	if (bbr) {
		spin_lock_bh(&peer->bbr_lock);
		uwg_bbr_on_ack(bbr, largest, bitmap, ack_delay_us,
			       ktime_get_ns());
		spin_unlock_bh(&peer->bbr_lock);
	}
	rcu_read_unlock();
}

static void uwg_ext_handle_ack(struct uwg_peer *peer, const u8 *payload,
			       size_t len)
{
	struct uwg_ext_ack ack;
	u64 bitmap;

	if (uwg_ext_parse_ack(payload, len, &ack))
		return;

	bitmap = get_unaligned_le64(ack.bitmap);
	peer->ack_tracker.largest = ack.largest;
	peer->ack_tracker.bitmap = bitmap;
	peer->ack_tracker.ack_delay_us = ack.ack_delay_us;
	peer->ack_tracker.bitmap_len = ack.bitmap_len;
	peer->ack_tracker.flags = ack.flags;
	peer->ack_tracker.valid = true;
	peer->ack_tracker.received++;
	peer->ack_tracker.last_ack_jiffies = jiffies;
	peer->ack_tracker.last_ack_ktime = ktime_get();

	uwg_ext_bbr_on_ack(peer, ack.largest, bitmap, ack.ack_delay_us);
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
	return ret ? UWG_EXT_RX_INVALID : UWG_EXT_RX_CONSUMED;
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

	if (skb->len < UWG_EXT_HEADER_LEN)
		return UWG_EXT_RX_NOT_EXTENSION;

	hdr = skb_header_pointer(skb, 0, sizeof(hdrbuf), hdrbuf);
	if (!hdr || !uwg_ext_detect(hdr, sizeof(hdrbuf)))
		return UWG_EXT_RX_NOT_EXTENSION;
	if (uwg_ext_parse_header(hdr, skb->len, &header))
		return UWG_EXT_RX_INVALID;

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
		uwg_ext_handle_ack(peer, ackbuf, header.payload_len);
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
