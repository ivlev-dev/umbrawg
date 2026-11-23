// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "header_protection.h"
#include "junk.h"
#include "queueing.h"
#include "timers.h"
#include "device.h"
#include "peer.h"
#include "socket.h"
#include "messages.h"
#include "cookie.h"
#include "type.h"
#include "aead.h"
#include "ext.h"
#include <linux/unaligned.h>
#include <linux/highmem.h>
#include <linux/jiffies.h>
#include <linux/module.h>

#include <linux/uio.h>
#include <linux/inetdevice.h>
#include <linux/socket.h>
#include <linux/random.h>
#include <linux/siphash.h>
#include <linux/preempt.h>
#include <net/ip_tunnels.h>
#include <net/udp.h>
#include <net/sock.h>

#define UWG_TX_MAX_ENTRIES 48
#define UWG_TX_MAX_SKBS 128
/* Hard ceiling of the UDP GSO_L4 segmentation: 65507 bytes of payload plus
 * the outer IP/UDP headers, one segment per tunnel datagram. The default keeps
 * a little headroom for a padded datagram on a 1420-byte tunnel MTU.
 */
#define UWG_GSO_SEGS_HARD_MAX 46
#define UWG_GSO_MAX_BYTES 65000

/*
 * Segments per GSO superdatagram. More segments amortise the per-aggregate
 * allocation (a full group is one high-order alloc_skb) and the per-datagram
 * underlay transmit path; fewer keep that allocation inside the slab pages
 * and make each underlay packet smaller. The default is the measured optimum
 * on the veth stand; the knob exists so the aggregate size can be A/B tested
 * without a rebuild.
 */
static unsigned int uwg_gso_segs_max = UWG_GSO_SEGS_HARD_MAX - 2;
module_param_named(gso_segs_max, uwg_gso_segs_max, uint, 0644);
MODULE_PARM_DESC(gso_segs_max,
		 "Maximum segments per UDP GSO superdatagram (1..46, default 44)");

/* Handshake outer TOS is sampled per frame: DSCP is not negotiated and the
 * peer ignores it, but a constant value is a stable fingerprint.
 */
static const u8 uwg_handshake_tos[] = {
	0x00, 0x28, HANDSHAKE_DSCP, 0xb8,
};

static u8 uwg_handshake_dscp(void)
{
	return uwg_handshake_tos[get_random_u32_below(ARRAY_SIZE(uwg_handshake_tos))];
}

static void uwg_packet_send_handshake_initiation(struct uwg_peer *peer)
{
	struct message_handshake_initiation packet;
	struct uwg_device *uwg = peer->device;
	void *buffer;
	u8 ds;
	u16 junk_packet_count, junk_packet_size;
	int i;
	struct jp_spec* spec;
	u16 min_timeout = !u16_range_is_zero(peer->device->rekey_timeout) ?
		u16_range_lo(peer->device->rekey_timeout) : REKEY_TIMEOUT;

	if (!uwg_birthdate_has_expired(atomic64_read(&peer->last_sent_handshake),
				      min_timeout))
		return; /* This function is rate limited. */

	atomic64_set(&peer->last_sent_handshake, ktime_get_coarse_boottime_ns());
	net_dbg_ratelimited("%s: Sending handshake initiation to peer %llu (%pISpfsc)\n",
			    peer->device->dev->name, peer->internal_id,
			    &peer->endpoint.addr);

	atomic_set(&peer->jp_packet_counter, get_random_u32());
	for (i = 0; i < ARRAY_SIZE(uwg->ispecs); ++i)
	{
		spec = &uwg->ispecs[i];
		if (spec->pkt_size > 0) {
			mutex_lock(&spec->lock);
			jp_spec_applymods(spec, peer);
			uwg_socket_send_buffer_to_peer(peer, spec->pkt, spec->pkt_size, 0, 0, false);
			atomic_inc(&peer->jp_packet_counter);
			mutex_unlock(&spec->lock);
		}
	}
	
	if (uwg->jc && uwg->jmax) {
		net_dbg_ratelimited("%s: Sending dummy junk packets to %llu (%pISpfsc)\n",
			    peer->device->dev->name, peer->internal_id,
			    &peer->endpoint.addr);

		junk_packet_count = uwg->jc;
		buffer = kzalloc(uwg->jmax, GFP_KERNEL);

		while (buffer && junk_packet_count-- > 0) {
			junk_packet_size = (u16) get_random_u32_inclusive(uwg->jmin, uwg->jmax);

			get_random_bytes(buffer, junk_packet_size);
			get_random_bytes(&ds, 1);
			uwg_socket_send_buffer_to_peer(peer, buffer, junk_packet_size, ds, 0, false);
		}

		kfree(buffer);
	}

	if (uwg_noise_handshake_create_initiation(&packet, &peer->handshake,
			u32_range_pick_one(uwg->init_header))) {
		uwg_cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		uwg_timers_any_authenticated_packet_traversal(peer);
		uwg_timers_any_authenticated_packet_sent(peer);
		atomic64_set(&peer->last_sent_handshake,
			     ktime_get_coarse_boottime_ns());
		uwg_socket_send_buffer_to_peer(peer, &packet, sizeof(packet),
					      uwg_handshake_dscp(),
					      uwg->init_padding, true);
		uwg_timers_handshake_initiated(peer);
	}
}

void uwg_packet_handshake_send_worker(struct work_struct *work)
{
	struct uwg_peer *peer = container_of(work, struct uwg_peer,
					    transmit_handshake_work);

	uwg_packet_send_handshake_initiation(peer);
	uwg_peer_put(peer);
}

void uwg_packet_send_queued_handshake_initiation(struct uwg_peer *peer,
						bool is_retry)
{
	u16 min_timeout = !u16_range_is_zero(peer->device->rekey_timeout) ?
		u16_range_lo(peer->device->rekey_timeout) : REKEY_TIMEOUT;

	if (!is_retry) {
		peer->timer_handshake_attempts = 0;
		peer->max_handshake_attempts = !u16_range_is_zero(peer->device->max_handshake_attempts) ? u16_range_pick_one(peer->device->max_handshake_attempts) : MAX_TIMER_HANDSHAKES;
	}

	rcu_read_lock_bh();
	/* We check last_sent_handshake here in addition to the actual function
	 * we're queueing up, so that we don't queue things if not strictly
	 * necessary:
	 */
	if (!uwg_birthdate_has_expired(atomic64_read(&peer->last_sent_handshake),
				      min_timeout) ||
			unlikely(READ_ONCE(peer->is_dead)))
		goto out;

	uwg_peer_get(peer);
	/* Queues up calling packet_send_queued_handshakes(peer), where we do a
	 * peer_put(peer) after:
	 */
	if (!queue_work(peer->device->handshake_send_wq,
			&peer->transmit_handshake_work))
		/* If the work was already queued, we want to drop the
		 * extra reference:
		 */
		uwg_peer_put(peer);
out:
	rcu_read_unlock_bh();
}

void uwg_packet_send_handshake_response(struct uwg_peer *peer)
{
	struct message_handshake_response packet;
	struct uwg_device *uwg = peer->device;

	atomic64_set(&peer->last_sent_handshake, ktime_get_coarse_boottime_ns());
	net_dbg_ratelimited("%s: Sending handshake response to peer %llu (%pISpfsc)\n",
			    peer->device->dev->name, peer->internal_id,
			    &peer->endpoint.addr);

	if (uwg_noise_handshake_create_response(&packet, &peer->handshake,
			u32_range_pick_one(uwg->resp_header))) {
		uwg_cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		if (uwg_noise_handshake_begin_session(&peer->handshake,
						     &peer->keypairs)) {
			uwg_timers_session_derived(peer);
			uwg_timers_any_authenticated_packet_traversal(peer);
			uwg_timers_any_authenticated_packet_sent(peer);
			atomic64_set(&peer->last_sent_handshake,
				     ktime_get_coarse_boottime_ns());
			uwg_socket_send_buffer_to_peer(peer, &packet,
						      sizeof(packet),
						      uwg_handshake_dscp(),
							  uwg->resp_padding, true);
			uwg_ext_maybe_send_caps(peer);
		}
	}
}

void uwg_packet_send_handshake_cookie(struct uwg_device *uwg,
				     struct sk_buff *initiating_skb,
				     __le32 sender_index)
{
	struct message_handshake_cookie packet;

	net_dbg_skb_ratelimited("%s: Sending cookie response for denied handshake message for %pISpfsc\n",
				uwg->dev->name, initiating_skb);
	uwg_cookie_message_create(&packet, initiating_skb, sender_index,
				 &uwg->cookie_checker,
				 u32_range_pick_one(uwg->cookie_header));
	uwg_socket_send_buffer_as_reply_to_skb(uwg, initiating_skb, &packet,
					      sizeof(packet),
						  uwg->cookie_padding);
}

static int key_fresh_timeout(struct uwg_peer *peer)
{
	return !u16_range_is_zero(peer->device->rekey_after_time) ? u16_range_pick_one(peer->device->rekey_after_time) : REKEY_AFTER_TIME;
}

static void keep_key_fresh(struct uwg_peer *peer)
{
	struct noise_keypair *keypair;
	bool send;

	rcu_read_lock_bh();
	keypair = rcu_dereference_bh(peer->keypairs.current_keypair);
	send = keypair && READ_ONCE(keypair->sending.is_valid) &&
	       (atomic64_read(&keypair->sending_counter) > REKEY_AFTER_MESSAGES ||
		(keypair->i_am_the_initiator &&
		 uwg_birthdate_has_expired(keypair->sending.birthdate, key_fresh_timeout(peer))));
	rcu_read_unlock_bh();

	if (unlikely(send))
		uwg_packet_send_queued_handshake_initiation(peer, false);
}

/*
 * Random tail of a FEC shard, shared by every shard of one block.
 *
 * The encoder pads all shards of a block to the same shard_len, but a plain
 * per-datagram random tail would give them different encrypted lengths again
 * and prevent the sender from aggregating them into one UDP GSO skb. The
 * tail is therefore a PRF of the block id under the sending key: it stays
 * unpredictable to an observer (and differs between blocks and keypairs),
 * while all shards of the block derive the same value.
 */
static unsigned int uwg_fec_shard_tail(const struct sk_buff *skb,
				       const struct noise_keypair *keypair)
{
	siphash_key_t key;
	const u8 *ext = skb->data;
	u32 block_id;

	/* The shard header is written by the FEC encoder right before the
	 * ext header. A malformed/empty frame never reaches here, but a
	 * fallback keeps the padding well formed if it ever does.
	 */
	if (unlikely(skb->len < UWG_EXT_HEADER_LEN + UWG_EXT_FEC_HEADER_LEN))
		return get_random_u32_below(MESSAGE_PADDING_MULTIPLE);

	block_id = get_unaligned_le32(ext + UWG_EXT_HEADER_LEN);
	memcpy(&key, keypair->sending.key, sizeof(key));
	return (unsigned int)(siphash_1u32(block_id, &key) %
			      MESSAGE_PADDING_MULTIPLE);
}

/*
 * Parity count of the FEC block the shard was cut from. A GSO
 * superdatagram is lost as a whole by the underlay, so a group may carry at
 * most this many shards: Reed-Solomon can then still rebuild the block.
 * Zero means "not a parsed shard" (or parity encoding failed); callers treat
 * it as no grouping. Only valid before encryption, while the ext header is
 * still plaintext.
 */
static u8 uwg_fec_shard_m(const struct sk_buff *skb)
{
	const u8 *ext = skb->data;

	if (unlikely(skb->len < UWG_EXT_HEADER_LEN + UWG_EXT_FEC_HEADER_LEN))
		return 0;
	if (unlikely(ext[0] != UWG_EXT_TAG || ext[1] != UWG_EXT_MAGIC_0 ||
		     ext[2] != UWG_EXT_MAGIC_1 || ext[3] != UWG_EXT_MAGIC_2 ||
		     ext[5] != UWG_EXT_KIND_FEC_SHARD))
		return 0;
	/* Wire layout of struct uwg_ext_fec_shard after the ext header:
	 * block_id +0, index +4, k +5, m +6.
	 */
	return ext[UWG_EXT_HEADER_LEN + 6];
}

static unsigned int calculate_skb_padding(struct sk_buff *skb)
{
	unsigned int padded_size, last_unit = skb->len;

	/* No MTU budget (FEC shards): still break the 16 byte grid with a
	 * random tail. The shard limit reserves room for it.
	 */
	if (unlikely(!PACKET_CB(skb)->mtu))
		return ALIGN(last_unit, MESSAGE_PADDING_MULTIPLE) - last_unit +
		       get_random_u32_below(MESSAGE_PADDING_MULTIPLE);

	/* We do this modulo business with the MTU, just in case the networking
	 * layer gives us a packet that's bigger than the MTU. In that case, we
	 * wouldn't want the final subtraction to overflow in the case of the
	 * padded_size being clamped. Fortunately, that's very rarely the case,
	 * so we optimize for that not happening.
	 */
	if (unlikely(last_unit > PACKET_CB(skb)->mtu))
		last_unit %= PACKET_CB(skb)->mtu;

	padded_size = min(PACKET_CB(skb)->mtu,
			  ALIGN(last_unit, MESSAGE_PADDING_MULTIPLE));
	/* The extra slack hides the 16 byte size grid of the transport as long
	 * as it fits the MTU budget; full-size datagrams simply get none.
	 */
	return padded_size - last_unit +
	       min_t(unsigned int, get_random_u32_below(MESSAGE_PADDING_MULTIPLE),
		     PACKET_CB(skb)->mtu - padded_size);
}

static bool encrypt_packet(struct sk_buff *skb, struct noise_keypair *keypair)
{
	struct uwg_peer *peer = keypair->entry.peer;
	unsigned int padding_len, plaintext_len, trailer_len, packet_len;
	struct scatterlist sg[MAX_SKB_FRAGS + 8];
	struct chacha_state state;
	struct message_data *header;
	struct sk_buff *trailer;
	char *crypto;
	int num_frags;
	unsigned int udp_window, window_max;
	int padding;
	u16_range_t content_padding_addition;

	padding = peer->device->transport_padding;
	content_padding_addition = peer->device->content_padding_addition;

	udp_window = padding + MESSAGE_MINIMUM_LENGTH + skb->len;
	window_max = uwg_peer_udp_window_max(peer->device);
	if (udp_window > window_max)
		udp_window = window_max;
	if (READ_ONCE(peer->udp_window) < udp_window)
		WRITE_ONCE(peer->udp_window, udp_window);

	/* Force hash calculation before encryption so that flow analysis is
	 * consistent over the inner packet.
	 */
	skb_get_hash(skb);

	/* Calculate lengths. */
	packet_len = skb->len + MESSAGE_MINIMUM_LENGTH + padding;
	/* PACKET_CB(skb)->padding is an override used by control frames: its
	 * value is the exclusive bound of the random tail they may carry.
	 * Every other TX path clears it in uwg_packet_send_staged_packets().
	 *
	 * FEC shards are padded by the block id, not by the per-datagram
	 * policies: only equal encrypted lengths can be GSO-aggregated, and
	 * a shard has no TUN MTU budget to hide a size window in anyway.
	 */
	if (unlikely(PACKET_CB(skb)->is_fec)) {
		padding_len = ALIGN(skb->len, MESSAGE_PADDING_MULTIPLE) -
			      skb->len + uwg_fec_shard_tail(skb, keypair);
	} else if (PACKET_CB(skb)->padding) {
		padding_len = get_random_u32_below(PACKET_CB(skb)->padding);
	} else if (!u16_range_is_zero(content_padding_addition)) {
		padding_len = uwg_peer_skb_randomize_padding_addition(peer, peer->device, packet_len);
	} else if (peer->device->random_trailers) {
		padding_len = uwg_peer_skb_random_trailer(peer, peer->device, packet_len);
	} else {
		padding_len = calculate_skb_padding(skb);
	}

	/* A FEC shard is bounded by the underlay MTU policy, not by the TUN
	 * MTU: the heuristics above are sized for the latter and a window
	 * derived trailer could inflate one shard past a whole datagram. The
	 * block already carries its own random slack inside the shard, so cap
	 * the outer tail at what UWG_FEC_SHARD_WIRE_OVERHEAD reserves.
	 */
	if (unlikely(PACKET_CB(skb)->is_fec) &&
	    padding_len > UWG_FEC_SHARD_TRAILER_MAX)
		padding_len = UWG_FEC_SHARD_TRAILER_MAX;

	trailer_len = padding_len + noise_encrypted_len(0);
	plaintext_len = skb->len + padding_len;

	/* Expand data section to have room for padding and auth tag. */
	num_frags = skb_cow_data(skb, trailer_len, &trailer);
	if (unlikely(num_frags < 0 || num_frags > ARRAY_SIZE(sg)))
		return false;

	/* Set the padding to zeros, and make sure it and the auth tag are part
	 * of the skb.
	 */
	memset(skb_tail_pointer(trailer), 0, padding_len);

	/* Expand head section to have room for our header and the network
	 * stack's headers.
	 */
	if (unlikely(skb_cow_head(skb, DATA_PACKET_HEAD_ROOM + padding) < 0))
		return false;

	/* Finalize checksum calculation for the inner packet, if required. */
	if (unlikely(skb->ip_summed == CHECKSUM_PARTIAL &&
		     skb_checksum_help(skb)))
		return false;

	/* Only after checksumming can we safely add on the padding at the end
	 * and the header.
	 */
	skb_set_inner_network_header(skb, 0);
	header = (struct message_data *)skb_push(skb, sizeof(*header));
	header->header.type = cpu_to_le32(
		u32_range_pick_one(peer->device->transport_header));
	header->key_idx = keypair->remote_index;
	header->counter = cpu_to_le64(PACKET_CB(skb)->nonce);
	pskb_put(skb, trailer, trailer_len);

	crypto = skb_push(skb, padding);
	get_random_bytes(crypto, padding);

	if (uwg_header_protection_init(&state, peer->device, crypto))
		chacha20_crypt(&state, (u8*)header, (u8*)header, sizeof(*header));

	if (keypair->sending_aead)
		return uwg_aead_encrypt(keypair->sending_aead, skb,
					sizeof(struct message_data) + padding,
					plaintext_len, PACKET_CB(skb)->nonce);

	/* Now we can encrypt the scattergather segments */
	sg_init_table(sg, num_frags);
	if (skb_to_sgvec(skb, sg, sizeof(struct message_data) + padding,
			 noise_encrypted_len(plaintext_len)) <= 0)
		return false;

	if (keypair->cipher == UWG_CIPHER_AES256GCM) {
		u8 aes_nonce[12] = { 0 };
		u8 tag[NOISE_AUTHTAG_LEN];
		struct aes_gcm_ctx ctx;
		struct scatterlist *part;
		unsigned int left = plaintext_len;

		put_unaligned_le64(PACKET_CB(skb)->nonce, aes_nonce + 4);
		aes_gcm_init(&ctx, aes_nonce, &keypair->sending_aes);
		for (part = sg; part && left; part = sg_next(part)) {
			unsigned int len = min_t(unsigned int, left, part->length);
			u8 *base = kmap_local_page(sg_page(part));
			u8 *addr = base + part->offset;

			aes_gcm_encrypt_update(&ctx, addr, addr, len);
			kunmap_local(base);
			left -= len;
		}
		aes_gcm_encrypt_final(&ctx, tag);
		if (skb_store_bits(skb,
				   sizeof(struct message_data) + padding + plaintext_len,
				   tag, sizeof(tag)))
			return false;
		return true;
	}

	return chacha20poly1305_encrypt_sg_inplace(sg, plaintext_len, NULL, 0,
						   PACKET_CB(skb)->nonce,
						   keypair->sending.key);
}

void uwg_packet_send_keepalive(struct uwg_peer *peer)
{
	struct sk_buff *skb;

	if (skb_queue_empty_lockless(&peer->staged_packet_queue)) {
		skb = alloc_skb(DATA_PACKET_HEAD_ROOM + MESSAGE_MINIMUM_LENGTH,
				GFP_ATOMIC);
		if (unlikely(!skb))
			return;
		skb_reserve(skb, DATA_PACKET_HEAD_ROOM);
		skb->dev = peer->device->dev;
		PACKET_CB(skb)->mtu = skb->dev->mtu;
		PACKET_CB(skb)->is_keepalive = true;
		PACKET_CB(skb)->is_fec = false;
		PACKET_CB(skb)->fec_m = 0;
		skb_queue_tail(&peer->staged_packet_queue, skb);
		net_dbg_ratelimited("%s: Sending keepalive packet to peer %llu (%pISpfsc)\n",
				    peer->device->dev->name, peer->internal_id,
				    &peer->endpoint.addr);
	}

	uwg_packet_send_staged_packets(peer);
}

static void uwg_packet_send_one(struct uwg_peer *peer, struct sk_buff *skb,
				bool *data_sent)
{
	bool is_keepalive = PACKET_CB(skb)->is_keepalive;
	u8 ds = PACKET_CB(skb)->ds;

	/* The socket layer owns the skb on every path. */
	if (likely(!uwg_socket_send_skb_to_peer(peer, skb, ds))) {
		if (!is_keepalive)
			*data_sent = true;
	}
}

static struct sk_buff *uwg_packet_gso_alloc(struct sk_buff **pkts,
					    unsigned int count, unsigned int len)
{
	unsigned int i;
	struct sk_buff *skb;

	skb = alloc_skb(DATA_PACKET_HEAD_ROOM + count * len, GFP_KERNEL);
	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, DATA_PACKET_HEAD_ROOM);
	for (i = 0; i < count; ++i) {
		void *dst = skb_put(skb, len);

		if (unlikely(skb_copy_bits(pkts[i], 0, dst, len))) {
			kfree_skb(skb);
			return NULL;
		}
	}

	/* The UDP header is pushed by the tunnel xmit path right at the
	 * current data pointer, so advertise the checksum start relative
	 * to where it will end up being.
	 */
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_headroom(skb) - sizeof(struct udphdr);
	skb->csum_offset = offsetof(struct udphdr, check);

	skb_shinfo(skb)->gso_size = len;
	skb_shinfo(skb)->gso_segs = count;
	skb_shinfo(skb)->gso_type = SKB_GSO_UDP_L4;
	return skb;
}

static bool uwg_packet_send_gso(struct uwg_peer *peer, struct sk_buff **pkts,
				unsigned int count, bool *data_sent)
{
	unsigned int i, len = pkts[0]->len;
	bool keepalive = false;
	u8 ds = PACKET_CB(pkts[0])->ds;
	struct sk_buff *agg;

	agg = uwg_packet_gso_alloc(pkts, count, len);
	if (unlikely(!agg))
		return false;

	for (i = 0; i < count; ++i)
		keepalive |= PACKET_CB(pkts[i])->is_keepalive;

	if (likely(!uwg_socket_send_skb_to_peer(peer, agg, ds))) {
		if (!keepalive)
			*data_sent = true;
	}

	for (i = 0; i < count; ++i)
		kfree_skb(pkts[i]);
	return true;
}

/* Send one window of encrypted skbs in order, aggregating neighbours of equal
 * size into UDP GSO superdatagrams. FEC shards of a block have the same
 * length by construction, so they aggregate the same way transport packets
 * do, but never together with non-FEC traffic: every GSO segment has to
 * remain a standalone ext frame with its own shard header.
 *
 * A GSO superdatagram is lost as a whole by the underlay, so a FEC group is
 * limited to the block's parity count: m shards may vanish without making the
 * block unrepairable. With m == 1 (and for blocks whose parity encoding
 * failed) shards are sent one per datagram, exactly like before the
 * aggregation existed.
 */
static void uwg_packet_send_batch(struct uwg_peer *peer, struct sk_buff **skbs,
				  unsigned int nskbs, bool *data_sent)
{
	unsigned int i, j;

	for (i = 0; i < nskbs; ) {
		unsigned int len = skbs[i]->len;
		unsigned int segs_max = clamp_t(unsigned int,
						READ_ONCE(uwg_gso_segs_max), 1,
						UWG_GSO_SEGS_HARD_MAX);
		unsigned int group_max = segs_max;
		u8 fec_m = PACKET_CB(skbs[i])->fec_m;
		u8 ds = PACKET_CB(skbs[i])->ds;
		bool is_fec = PACKET_CB(skbs[i])->is_fec;

		if (is_fec)
			group_max = min_t(unsigned int, fec_m ? fec_m : 1,
					  segs_max);

		for (j = i + 1; j < nskbs; ++j) {
			if (skbs[j]->len != len ||
			    PACKET_CB(skbs[j])->ds != ds ||
			    PACKET_CB(skbs[j])->is_fec != is_fec ||
			    PACKET_CB(skbs[j])->fec_m != fec_m ||
			    PACKET_CB(skbs[j])->is_keepalive !=
				    PACKET_CB(skbs[i])->is_keepalive)
				break;
			if (j - i >= group_max)
				break;
			if ((j - i + 1) * len > UWG_GSO_MAX_BYTES)
				break;
		}

		if (j - i > 1 &&
		    uwg_packet_send_gso(peer, skbs + i, j - i, data_sent)) {
			i = j;
			continue;
		}

		for (; i < j; ++i)
			uwg_packet_send_one(peer, skbs[i], data_sent);
	}
}

static void uwg_packet_create_data_done(struct uwg_peer *peer,
					struct sk_buff **entries,
					unsigned int entries_len)
{
	struct sk_buff *skbs[UWG_TX_MAX_SKBS];
	unsigned int nskbs = 0, i;
	bool data_sent = false;

	/* Flatten the crypted chains into wire-order batches. The window is
	 * bounded so the array stays on the stack; it must be flushed before
	 * more skbs are appended. Draining the overflow out of band (the old
	 * behaviour) sent later packets first and put inner TCP out of order,
	 * which is exactly the GSO burst the superpacket segmentation was
	 * supposed to prevent.
	 */
	for (i = 0; i < entries_len; ++i) {
		struct sk_buff *skb, *next;

		skb_list_walk_safe(entries[i], skb, next) {
			skb_mark_not_on_list(skb);
			if (unlikely(nskbs == UWG_TX_MAX_SKBS)) {
				uwg_packet_send_batch(peer, skbs, nskbs,
						      &data_sent);
				nskbs = 0;
			}
			skbs[nskbs++] = skb;
		}
	}

	uwg_timers_any_authenticated_packet_traversal(peer);
	uwg_timers_any_authenticated_packet_sent(peer);

	if (nskbs)
		uwg_packet_send_batch(peer, skbs, nskbs, &data_sent);

	if (likely(data_sent))
		uwg_timers_data_sent(peer);

	keep_key_fresh(peer);
}

void uwg_packet_tx_worker(struct work_struct *work)
{
	struct uwg_peer *peer = container_of(work, struct uwg_peer, transmit_packet_work);
	struct sk_buff *entries[UWG_TX_MAX_ENTRIES];
	struct noise_keypair *keypairs[UWG_TX_MAX_ENTRIES];
	unsigned int n, i;

	for (;;) {
		struct sk_buff *first;
		enum packet_state state;

		n = 0;
		while (n < UWG_TX_MAX_ENTRIES &&
		       (first = uwg_prev_queue_peek(&peer->tx_queue)) != NULL &&
		       (state = atomic_read_acquire(&PACKET_CB(first)->state)) !=
			       PACKET_STATE_UNCRYPTED) {
			uwg_prev_queue_drop_peeked(&peer->tx_queue);
			if (likely(state == PACKET_STATE_CRYPTED)) {
				entries[n] = first;
				keypairs[n] = PACKET_CB(first)->keypair;
				++n;
				continue;
			}
			uwg_noise_keypair_put(PACKET_CB(first)->keypair, false);
			kfree_skb_list(first);
			uwg_peer_put(peer);
		}

		if (!n)
			break;

		uwg_packet_create_data_done(peer, entries, n);

		for (i = 0; i < n; ++i) {
			uwg_noise_keypair_put(keypairs[i], false);
			uwg_peer_put(peer);
		}

		if (need_resched())
			cond_resched();
	}
}

static void uwg_packet_encrypt_chain(struct sk_buff *first)
{
	enum packet_state state = PACKET_STATE_CRYPTED;
	struct sk_buff *skb, *next;

	skb_list_walk_safe(first, skb, next) {
		if (likely(encrypt_packet(skb, PACKET_CB(first)->keypair))) {
			uwg_reset_packet(skb, true);
		} else {
			state = PACKET_STATE_DEAD;
			break;
		}
	}
	uwg_queue_enqueue_per_peer_tx(first, state);

	if (need_resched())
		cond_resched();
}

void uwg_packet_encrypt_worker(struct work_struct *work)
{
	struct multicore_worker *worker = container_of(work,
						       struct multicore_worker,
						       work);
	struct crypt_queue *queue = worker->ptr;
	struct crypt_queue *victim;
	struct sk_buff *first;

	for (;;) {
		while ((first = ptr_ring_consume_bh(&queue->ring)) != NULL)
			uwg_packet_encrypt_chain(first);

		/* An idle CPU helps a single flow that outgrew its ring. */
		victim = uwg_crypt_steal_claim(queue);
		if (victim) {
			while ((first = ptr_ring_consume_bh(&victim->ring)) != NULL)
				uwg_packet_encrypt_chain(first);
		}

		if (uwg_queue_wakeup_drained(worker, queue))
			break;
	}
}

static void uwg_packet_create_data(struct uwg_peer *peer, struct sk_buff *first)
{
	struct uwg_device *uwg = peer->device;
	int ret = -EINVAL;

	rcu_read_lock_bh();
	if (unlikely(READ_ONCE(peer->is_dead)))
		goto err;

	ret = uwg_queue_enqueue_per_device_and_peer(&uwg->encrypt_queue, &peer->tx_queue, first,
						   uwg->packet_crypt_wq);
	if (unlikely(ret == -EPIPE)) {
		/* Every per-CPU ring is full (the spill path failed too): the
		 * chain will be dropped by the tx worker, so account for it
		 * where the drop happens.
		 */
		DEV_STATS_INC(uwg->dev, tx_dropped);
		net_dbg_ratelimited("%s: all per-CPU encrypt rings full, dropping chain\n",
				    uwg->dev->name);
		uwg_queue_enqueue_per_peer_tx(first, PACKET_STATE_DEAD);
	}
err:
	rcu_read_unlock_bh();
	if (likely(!ret || ret == -EPIPE))
		return;
	uwg_noise_keypair_put(PACKET_CB(first)->keypair, false);
	uwg_peer_put(peer);
	kfree_skb_list(first);
}

int uwg_packet_send_control(struct uwg_peer *peer, const u8 *frame, size_t len)
{
	struct uwg_device *uwg = peer->device;
	struct noise_keypair *keypair;
	struct sk_buff *skb;

	if (unlikely(!len || len > U16_MAX))
		return -EMSGSIZE;
	if (unlikely(READ_ONCE(peer->is_dead)))
		return -ENODEV;

	rcu_read_lock_bh();
	keypair = uwg_noise_keypair_get(
		rcu_dereference_bh(peer->keypairs.current_keypair));
	rcu_read_unlock_bh();
	if (unlikely(!keypair))
		return -ENOKEY;
	if (unlikely(!READ_ONCE(keypair->sending.is_valid)) ||
	    unlikely(uwg_birthdate_has_expired(keypair->sending.birthdate,
					       REJECT_AFTER_TIME)) ||
	    unlikely(atomic64_read(&keypair->sending_counter) >=
		     REJECT_AFTER_MESSAGES)) {
		uwg_noise_keypair_put(keypair, false);
		return -EKEYREJECTED;
	}
	skb = alloc_skb(DATA_PACKET_HEAD_ROOM + len, GFP_ATOMIC);
	if (unlikely(!skb)) {
		uwg_noise_keypair_put(keypair, false);
		return -ENOMEM;
	}
	skb_reserve(skb, DATA_PACKET_HEAD_ROOM);
	skb_put_data(skb, frame, len);
	skb->dev = uwg->dev;
	PACKET_CB(skb)->mtu = skb->dev->mtu;
	PACKET_CB(skb)->ds = 0;
	PACKET_CB(skb)->is_keepalive = false;
	PACKET_CB(skb)->is_fec = false;
	PACKET_CB(skb)->fec_m = 0;
	/* CAPS frames are tiny: cap their random tail instead of letting the
	 * transport padding policy inflate them to the UDP window.
	 */
	PACKET_CB(skb)->padding = UWG_EXT_CONTROL_PADDING_MAX + 1;
	PACKET_CB(skb)->nonce =
		atomic64_inc_return(&keypair->sending_counter) - 1;
	if (unlikely(PACKET_CB(skb)->nonce >= REJECT_AFTER_MESSAGES)) {
		WRITE_ONCE(keypair->sending.is_valid, false);
		uwg_noise_keypair_put(keypair, false);
		kfree_skb(skb);
		return -EOVERFLOW;
	}
	PACKET_CB(skb)->keypair = keypair;
	uwg_peer_get(peer);
	uwg_packet_create_data(peer, skb);
	return 0;
}

void uwg_packet_purge_staged_packets(struct uwg_peer *peer)
{
	spin_lock_bh(&peer->staged_packet_queue.lock);
	DEV_STATS_ADD(peer->device->dev, tx_dropped,
		      peer->staged_packet_queue.qlen);
	__skb_queue_purge(&peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);
}

void uwg_packet_send_fec_frames(struct uwg_peer *peer,
				struct sk_buff_head *frames)
{
	if (skb_queue_empty(frames))
		return;
	if (unlikely(READ_ONCE(peer->is_dead))) {
		__skb_queue_purge(frames);
		return;
	}
	spin_lock_bh(&peer->staged_packet_queue.lock);
	skb_queue_splice_tail(frames, &peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);
	uwg_packet_send_staged_packets(peer);
}

/* A GSO superpacket hands a whole burst of inner segments to the TX path at
 * once. The xmit path segments before FEC, so uwg_fec_tx_push() only sees
 * packets that fit one shard; this repeats the invariant for any other
 * producer of the staged queue, and gives every segment its own nonce and its
 * own place in the ciphertext order instead of one nonce for a burst.
 *
 * Segments replace the superpacket in place, so the queue order stays the
 * inner TCP order. A segmentation failure keeps the original: dropping it
 * here would lose a whole burst, and the legacy path at least delivers it.
 */
static void uwg_segment_gso(struct sk_buff_head *packets)
{
	struct sk_buff *skb, *next, *prev = NULL;

	skb_queue_walk_safe(packets, skb, next) {
		struct sk_buff *segs, *seg, *seg_next;
		struct packet_cb cb;

		if (!skb_is_gso(skb)) {
			prev = skb;
			continue;
		}
		segs = skb_gso_segment(skb, 0);
		if (IS_ERR_OR_NULL(segs)) {
			prev = skb;
			continue;
		}

		/* The superpacket's CB carries what the xmit path decided: the
		 * MTU it was checked against and the FEC/keepalive flags. Copy
		 * it before the original is freed; nonce, keypair and state
		 * stay unset for the per-segment pass below.
		 */
		cb.mtu = PACKET_CB(skb)->mtu;
		cb.ds = PACKET_CB(skb)->ds;
		cb.type = PACKET_CB(skb)->type;
		cb.padding = PACKET_CB(skb)->padding;
		cb.is_keepalive = PACKET_CB(skb)->is_keepalive;
		cb.is_fec = PACKET_CB(skb)->is_fec;
		cb.fec_m = PACKET_CB(skb)->fec_m;

		__skb_unlink(skb, packets);
		kfree_skb(skb);

		for (seg = segs; seg; seg = seg_next) {
			seg_next = seg->next;
			skb_mark_not_on_list(seg);
			PACKET_CB(seg)->mtu = cb.mtu;
			PACKET_CB(seg)->ds = cb.ds;
			PACKET_CB(seg)->type = cb.type;
			PACKET_CB(seg)->padding = cb.padding;
			PACKET_CB(seg)->is_keepalive = cb.is_keepalive;
			PACKET_CB(seg)->is_fec = cb.is_fec;
			PACKET_CB(seg)->fec_m = cb.fec_m;
			if (prev)
				__skb_queue_after(packets, prev, seg);
			else
				__skb_queue_head(packets, seg);
			prev = seg;
		}
	}
}

void uwg_packet_send_staged_packets(struct uwg_peer *peer)
{
	struct noise_keypair *keypair;
	struct sk_buff_head packets;
	struct sk_buff *skb;

	/* The steal -> nonce -> tx_queue enqueue sequence must be atomic per
	 * peer. Otherwise two producers can steal their batches in one order
	 * (old packets first) and enqueue the chains in the other (a later
	 * batch wins the race), and the TX worker sends newer inner TCP data
	 * before older data. The per-peer crypt queue already fixes the
	 * encryption order; this fixes the order the chains enter it.
	 */
	spin_lock_bh(&peer->tx_order_lock);

	/* Steal the current queue into our local one. */
	__skb_queue_head_init(&packets);
	spin_lock_bh(&peer->staged_packet_queue.lock);
	skb_queue_splice_init(&peer->staged_packet_queue, &packets);
	spin_unlock_bh(&peer->staged_packet_queue.lock);
	if (unlikely(skb_queue_empty(&packets)))
		goto out_empty;

	/* Must run before nonces are handed out: one nonce per inner segment
	 * is what keeps replay protection, FEC coverage and the ciphertext
	 * order aligned with the inner TCP sequence.
	 */
	uwg_segment_gso(&packets);
	if (unlikely(skb_queue_empty(&packets)))
		goto out_empty;

	/* First we make sure we have a valid reference to a valid key. */
	rcu_read_lock_bh();
	keypair = uwg_noise_keypair_get(
		rcu_dereference_bh(peer->keypairs.current_keypair));
	rcu_read_unlock_bh();
	if (unlikely(!keypair))
		goto out_nokey;
	if (unlikely(!READ_ONCE(keypair->sending.is_valid)))
		goto out_nokey;
	if (unlikely(uwg_birthdate_has_expired(keypair->sending.birthdate,
					      REJECT_AFTER_TIME)))
		goto out_invalid;

	/* After we know we have a somewhat valid key, we now try to assign
	 * nonces to all of the packets in the queue. If we can't assign nonces
	 * for all of them, we just consider it a failure and wait for the next
	 * handshake.
	 */
	skb_queue_walk(&packets, skb) {
		/* 0 for no outer TOS: no leak. TODO: at some later point, we
		 * might consider using flowi->tos as outer instead.
		 */
		PACKET_CB(skb)->ds = PACKET_CB(skb)->is_fec ?
			0 : ip_tunnel_ecn_encap(0, ip_hdr(skb), skb);
		/* Drop any stale padding override: only control frames, which
		 * do not pass through this path, may set one.
		 */
		PACKET_CB(skb)->padding = 0;
		/* The FEC ext header is still plaintext here; the GSO
		 * grouping runs after encryption and cannot read it anymore.
		 */
		PACKET_CB(skb)->fec_m = PACKET_CB(skb)->is_fec ?
			uwg_fec_shard_m(skb) : 0;
		PACKET_CB(skb)->nonce =
				atomic64_inc_return(&keypair->sending_counter) - 1;
		if (unlikely(PACKET_CB(skb)->nonce >= REJECT_AFTER_MESSAGES))
			goto out_invalid;
	}

	packets.prev->next = NULL;
	uwg_peer_get(keypair->entry.peer);
	PACKET_CB(packets.next)->keypair = keypair;
	uwg_packet_create_data(peer, packets.next);
	spin_unlock_bh(&peer->tx_order_lock);
	return;

out_empty:
	spin_unlock_bh(&peer->tx_order_lock);
	return;

out_invalid:
	WRITE_ONCE(keypair->sending.is_valid, false);
out_nokey:
	uwg_noise_keypair_put(keypair, false);
	spin_unlock_bh(&peer->tx_order_lock);

	/* We orphan the packets if we're waiting on a handshake, so that they
	 * don't block a socket's pool.
	 */
	skb_queue_walk(&packets, skb)
		skb_orphan(skb);
	/* Then we put them back on the top of the queue. We're not too
	 * concerned about accidentally getting things a little out of order if
	 * packets are being added really fast, because this queue is for before
	 * packets can even be sent and it's small anyway.
	 */
	spin_lock_bh(&peer->staged_packet_queue.lock);
	skb_queue_splice(&packets, &peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);

	/* If we're exiting because there's something wrong with the key, it
	 * means we should initiate a new handshake.
	 */
	uwg_packet_send_queued_handshake_initiation(peer, false);
}
