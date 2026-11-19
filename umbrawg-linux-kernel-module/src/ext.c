// SPDX-License-Identifier: GPL-2.0

#include "ext.h"
#include "peer.h"
#include "device.h"

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

	if (!shard->k || !shard->m)
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

	memset(caps, 0, sizeof(*caps));
	caps->ack_interval = UWG_EXT_DEFAULT_ACK_INTERVAL;

	if (uwg->bbr_mode != UWG_BBR_MODE_OFF)
		flags |= UWG_EXT_CAP_BBR | UWG_EXT_CAP_ACK;

	if (uwg->fec_mode != UWG_FEC_MODE_OFF) {
		flags |= UWG_EXT_CAP_FEC;
		if (uwg->fec_mode == UWG_FEC_MODE_ADAPTIVE) {
			flags |= UWG_EXT_CAP_FEC_ADAPTIVE;
			caps->fec_k = UWG_EXT_DEFAULT_FEC_K;
			caps->fec_m = UWG_EXT_DEFAULT_FEC_M;
		} else {
			caps->fec_k = (u8)(uwg->fec_mode >> 8);
			caps->fec_m = (u8)uwg->fec_mode;
		}
	}

	caps->flags = flags;
}

void uwg_ext_peer_init(struct uwg_peer *peer)
{
	memset(&peer->caps, 0, sizeof(peer->caps));
	memset(&peer->ack_tracker, 0, sizeof(peer->ack_tracker));
	uwg_ext_local_caps(peer->device, &peer->caps.local);
}

static void uwg_ext_handle_caps(struct uwg_peer *peer, const u8 *payload,
				size_t len)
{
	struct uwg_ext_caps caps;

	if (uwg_ext_parse_caps(payload, len, &caps))
		return;
	uwg_ext_local_caps(peer->device, &peer->caps.local);
	peer->caps.peer = caps;
	peer->caps.peer_valid = true;
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
}

static enum uwg_ext_rx_result uwg_ext_handle_fec_shard(const u8 *payload,
						       size_t len)
{
	struct uwg_ext_fec_shard shard;

	if (uwg_ext_parse_fec_shard(payload, len, &shard))
		return UWG_EXT_RX_INVALID;
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
		return uwg_ext_handle_fec_shard(fecbuf, header.payload_len);
	default:
		return UWG_EXT_RX_INVALID;
	}
}
