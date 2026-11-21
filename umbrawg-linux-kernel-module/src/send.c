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
#include "bbr.h"
#include <linux/unaligned.h>
#include <linux/highmem.h>
#include <linux/jiffies.h>

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
#define UWG_GSO_SEGS_MAX 44
#define UWG_GSO_MAX_BYTES 65000

/* Datagrams below this size are never delayed: pacing them would only add
 * latency to ACKs, keepalives and interactive traffic.
 */
#define UWG_TX_PACE_MIN_BYTES 512
#define UWG_TX_PACE_MAX_NS UWG_BBR_DRAIN_DELAY_MAX_NS

/*
 * A staged batch withheld by the congestion window is released
 * unconditionally after this long. The window only reopens on ACKs, so
 * without the timeout a lost ACK stream would park the tunnel for good.
 */
#define UWG_TX_CWND_BLOCK_MAX_NS (5ULL * NSEC_PER_MSEC)

/*
 * After the cwnd gate cut a batch short, pacing stays quiet for this long:
 * the gate already spaces batches at cwnd/RTT, and a token-bucket sleep on
 * top of it would add a second throughput ceiling. The window covers the
 * encrypt-queue hand-off, so ordinary batches are still paced.
 */
#define UWG_TX_CWND_PACE_QUIET_NS (2ULL * NSEC_PER_MSEC)

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
		PACKET_CB(skb)->pace_len = 0;
		skb_queue_tail(&peer->staged_packet_queue, skb);
		net_dbg_ratelimited("%s: Sending keepalive packet to peer %llu (%pISpfsc)\n",
				    peer->device->dev->name, peer->internal_id,
				    &peer->endpoint.addr);
	}

	uwg_packet_send_staged_packets(peer);
}

static void uwg_packet_bbr_on_send(struct uwg_peer *peer,
				   struct sk_buff_head *packets,
				   u64 keypair_id)
{
	struct uwg_bbr *bbr;
	struct sk_buff *skb;
	u64 now_ns;

	if (READ_ONCE(peer->device->bbr_mode) == UWG_BBR_MODE_OFF)
		return;

	rcu_read_lock();
	bbr = uwg_peer_bbr_lookup(peer);
	if (unlikely(!bbr)) {
		rcu_read_unlock();
		return;
	}

	now_ns = ktime_get_ns();
	spin_lock_bh(&peer->bbr_lock);
	/* FEC lowers the interface MTU to what fits one shard, so the
	 * controller's unit of loss must follow it instead of a fixed 1400:
	 * min_cwnd and the pacer burst are derived from it.
	 */
	uwg_bbr_set_mss(bbr, READ_ONCE(peer->device->dev->mtu));
	skb_queue_walk(packets, skb) {
		if (PACKET_CB(skb)->is_keepalive) {
			/* Keepalives are not tracked in the ring, but their
			 * counters appear in ACK.largest.
			 */
			uwg_bbr_note_sent(bbr, keypair_id, PACKET_CB(skb)->nonce);
			continue;
		}
		uwg_bbr_on_send(bbr, keypair_id, PACKET_CB(skb)->nonce, skb->len,
				now_ns);
	}
	spin_unlock_bh(&peer->bbr_lock);
	rcu_read_unlock();
}

static void uwg_packet_bbr_on_sent(struct uwg_peer *peer,
				   struct sk_buff *const *skbs,
				   unsigned int count)
{
	struct uwg_bbr *bbr;
	u64 now_ns;
	unsigned int i;

	if (READ_ONCE(peer->device->bbr_mode) == UWG_BBR_MODE_OFF)
		return;

	rcu_read_lock();
	bbr = uwg_peer_bbr_lookup(peer);
	if (unlikely(!bbr)) {
		rcu_read_unlock();
		return;
	}

	/* One timestamp and one lock for the whole GSO group keeps the
	 * intra-group spacing out of the RTT samples.
	 */
	now_ns = ktime_get_ns();
	spin_lock_bh(&peer->bbr_lock);
	for (i = 0; i < count; i++) {
		if (PACKET_CB(skbs[i])->is_keepalive)
			continue;
		uwg_bbr_on_sent(bbr, PACKET_CB(skbs[i])->nonce, now_ns);
	}
	spin_unlock_bh(&peer->bbr_lock);
	rcu_read_unlock();
}

/*
 * Datagrams that were registered with uwg_bbr_on_send() but never reached
 * the wire must leave inflight; otherwise a failing queue or crypto path
 * slowly inflates the window.
 */
static void uwg_packet_bbr_on_drop(struct uwg_peer *peer, struct sk_buff *list)
{
	struct sk_buff *skb, *next;
	struct uwg_bbr *bbr;

	if (READ_ONCE(peer->device->bbr_mode) == UWG_BBR_MODE_OFF)
		return;

	rcu_read_lock();
	bbr = uwg_peer_bbr_lookup(peer);
	if (bbr) {
		spin_lock_bh(&peer->bbr_lock);
		skb_list_walk_safe(list, skb, next) {
			if (!PACKET_CB(skb)->is_keepalive)
				uwg_bbr_on_drop(bbr, PACKET_CB(skb)->nonce);
		}
		spin_unlock_bh(&peer->bbr_lock);
	}
	rcu_read_unlock();
}

/*
 * Same release for the datagrams the underlay refused to take. The single
 * path has only the nonce left (the socket layer freed the skb); the GSO
 * path still owns its segments and passes them in.
 */
static void uwg_packet_bbr_on_drop_one(struct uwg_peer *peer, u64 nonce)
{
	struct uwg_bbr *bbr;

	if (READ_ONCE(peer->device->bbr_mode) == UWG_BBR_MODE_OFF)
		return;

	rcu_read_lock();
	bbr = uwg_peer_bbr_lookup(peer);
	if (bbr) {
		spin_lock_bh(&peer->bbr_lock);
		uwg_bbr_on_drop(bbr, nonce);
		spin_unlock_bh(&peer->bbr_lock);
	}
	rcu_read_unlock();
}

static void uwg_packet_bbr_on_drop_skbs(struct uwg_peer *peer,
					struct sk_buff *const *skbs,
					unsigned int count)
{
	struct uwg_bbr *bbr;
	unsigned int i;

	if (READ_ONCE(peer->device->bbr_mode) == UWG_BBR_MODE_OFF)
		return;

	rcu_read_lock();
	bbr = uwg_peer_bbr_lookup(peer);
	if (bbr) {
		spin_lock_bh(&peer->bbr_lock);
		for (i = 0; i < count; ++i) {
			if (PACKET_CB(skbs[i])->is_keepalive)
				continue;
			uwg_bbr_on_drop(bbr, PACKET_CB(skbs[i])->nonce);
		}
		spin_unlock_bh(&peer->bbr_lock);
	}
	rcu_read_unlock();
}

static u64 uwg_packet_pace_delay_ns(struct uwg_peer *peer, unsigned int len)
{
	struct uwg_bbr *bbr;
	u64 delay_ns = 0;

	rcu_read_lock();
	bbr = uwg_peer_bbr_lookup(peer);
	if (bbr) {
		spin_lock_bh(&peer->bbr_lock);
		delay_ns = uwg_bbr_next_delay_ns(bbr, len, ktime_get_ns());
		spin_unlock_bh(&peer->bbr_lock);
	}
	rcu_read_unlock();
	return delay_ns;
}

/*
 * Spreads bulk datagrams over time at the BBR pacing rate. Only called from
 * the tx worker, i.e. process context: if that ever changes and the caller
 * sits in softirq or holds a spinlock, pacing is skipped rather than allowed
 * to sleep.
 */
static void uwg_packet_pace(struct uwg_peer *peer, unsigned int len)
{
	u64 delay_ns, gate_ns;
	u32 delay_us;

	if (len < UWG_TX_PACE_MIN_BYTES)
		return;
	if (READ_ONCE(peer->device->bbr_mode) != UWG_BBR_MODE_ON)
		return;
	if (!preemptible())
		return;

	/* A batch the cwnd gate cut short is already spaced by the window:
	 * sleeping it out here as well would halve the achieved rate.
	 */
	gate_ns = READ_ONCE(peer->cwnd_gate_ns);
	if (gate_ns && ktime_get_ns() - gate_ns < UWG_TX_CWND_PACE_QUIET_NS)
		return;

	delay_ns = uwg_packet_pace_delay_ns(peer, len);
	if (delay_ns < NSEC_PER_USEC)
		return;
	delay_ns = min(delay_ns, UWG_TX_PACE_MAX_NS);
	delay_us = (u32)div_u64(delay_ns + NSEC_PER_USEC - 1, NSEC_PER_USEC);
	usleep_range(delay_us, delay_us + delay_us / 4 + 1);
}

static void uwg_packet_send_one(struct uwg_peer *peer, struct sk_buff *skb,
				bool *data_sent, bool pace)
{
	bool is_keepalive = PACKET_CB(skb)->is_keepalive;
	u32 pace_len = PACKET_CB(skb)->pace_len;
	u64 nonce = PACKET_CB(skb)->nonce;
	u8 ds = PACKET_CB(skb)->ds;

	/* FEC blocks are paced as a whole: only the first shard carries the
	 * block length in pace_len, the rest are sent right after it.
	 */
	if (pace && !is_keepalive) {
		if (pace_len)
			uwg_packet_pace(peer, pace_len);
		else if (!PACKET_CB(skb)->is_fec)
			uwg_packet_pace(peer, skb->len);
	}

	uwg_packet_bbr_on_sent(peer, &skb, 1);

	/* The socket layer owns the skb on every path. A refused datagram
	 * (no route, dead endpoint) has already consumed a ring slot, so it
	 * must leave inflight here instead of waiting for the watermark.
	 */
	if (likely(!uwg_socket_send_skb_to_peer(peer, skb, ds))) {
		if (!is_keepalive)
			*data_sent = true;
		return;
	}
	if (!is_keepalive)
		uwg_packet_bbr_on_drop_one(peer, nonce);
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

	/* Each segment consumed a nonce and a ring slot; the aggregate skb is
	 * sent as one device packet but must update all of them. The segments
	 * stay alive until the transmit result is known: a refused aggregate
	 * has to return every slot to the window.
	 */
	uwg_packet_bbr_on_sent(peer, pkts, count);
	for (i = 0; i < count; ++i)
		keepalive |= PACKET_CB(pkts[i])->is_keepalive;

	if (likely(!uwg_socket_send_skb_to_peer(peer, agg, ds))) {
		if (!keepalive)
			*data_sent = true;
	} else {
		uwg_packet_bbr_on_drop_skbs(peer, pkts, count);
	}

	for (i = 0; i < count; ++i)
		kfree_skb(pkts[i]);
	return true;
}

/*
 * Pacing cost of one datagram. FEC blocks are charged once, on the shard
 * that carries the whole block length in pace_len; the other shards of the
 * block add nothing, so a GSO group of shards is never charged twice.
 */
static u32 uwg_packet_pace_bytes(struct sk_buff *skb)
{
	u32 pace_len = PACKET_CB(skb)->pace_len;

	if (PACKET_CB(skb)->is_keepalive)
		return 0;
	if (pace_len)
		return pace_len;
	if (PACKET_CB(skb)->is_fec)
		return 0;
	return skb->len;
}

static void uwg_packet_create_data_done(struct uwg_peer *peer,
					struct sk_buff **entries,
					unsigned int entries_len)
{
	struct sk_buff *skbs[UWG_TX_MAX_SKBS];
	unsigned int nskbs = 0, i, j;
	bool data_sent = false;
	u32 pace_len = 0;

	for (i = 0; i < entries_len; ++i) {
		struct sk_buff *skb, *next;

		skb_list_walk_safe(entries[i], skb, next) {
			skb_mark_not_on_list(skb);
			if (likely(nskbs < UWG_TX_MAX_SKBS)) {
				skbs[nskbs++] = skb;
				pace_len += uwg_packet_pace_bytes(skb);
			} else {
				uwg_packet_send_one(peer, skb, &data_sent, true);
			}
		}
	}

	uwg_timers_any_authenticated_packet_traversal(peer);
	uwg_timers_any_authenticated_packet_sent(peer);

	/* One sleep for the whole batch instead of one per datagram. */
	if (pace_len)
		uwg_packet_pace(peer, pace_len);

	/* Neighbouring datagrams of equal size share one GSO skb. FEC shards of
	 * a block have the same length by construction, so they aggregate the
	 * same way transport packets do, but never together with non-FEC
	 * traffic: every GSO segment has to remain a standalone ext frame with
	 * its own shard header. Pacing is charged once per block by the shard
	 * carrying pace_len, see uwg_packet_pace_bytes().
	 *
	 * A GSO superdatagram is lost as a whole by the underlay, so a FEC
	 * group is limited to the block's parity count: m shards may vanish
	 * without making the block unrepairable. With m == 1 (and for blocks
	 * whose parity encoding failed) shards are sent one per datagram,
	 * exactly like before the aggregation existed.
	 */
	for (i = 0; i < nskbs; ) {
		unsigned int len = skbs[i]->len;
		unsigned int group_max = UWG_GSO_SEGS_MAX;
		u8 fec_m = PACKET_CB(skbs[i])->fec_m;
		u8 ds = PACKET_CB(skbs[i])->ds;
		bool is_fec = PACKET_CB(skbs[i])->is_fec;

		if (is_fec)
			group_max = min_t(unsigned int, fec_m ? fec_m : 1,
					  UWG_GSO_SEGS_MAX);

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
		    uwg_packet_send_gso(peer, skbs + i, j - i, &data_sent)) {
			i = j;
			continue;
		}

		for (; i < j; ++i)
			uwg_packet_send_one(peer, skbs[i], &data_sent, false);
	}

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
			uwg_packet_bbr_on_drop(peer, first);
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

void uwg_packet_encrypt_worker(struct work_struct *work)
{
	struct multicore_worker *worker = container_of(work,
						       struct multicore_worker,
						       work);
	struct crypt_queue *queue = worker->ptr;
	struct sk_buff *first, *skb, *next;

	for (;;) {
		while ((first = ptr_ring_consume_bh(&queue->ring)) != NULL) {
			enum packet_state state = PACKET_STATE_CRYPTED;

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
	if (unlikely(ret == -EPIPE))
		uwg_queue_enqueue_per_peer_tx(first, PACKET_STATE_DEAD);
err:
	rcu_read_unlock_bh();
	if (likely(!ret || ret == -EPIPE))
		return;
	uwg_packet_bbr_on_drop(peer, first);
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
	if (READ_ONCE(uwg->bbr_mode) != UWG_BBR_MODE_OFF)
		uwg_peer_bbr_keypair_changed(peer, keypair->internal_id);

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
	PACKET_CB(skb)->pace_len = 0;
	/* CAPS/ACK frames are tiny: cap their random tail instead of letting
	 * the transport padding policy inflate them to the UDP window.
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
	/* Control frames consume wire counters too: record the nonce so the
	 * peer's ACKs for them are not rejected by the BBR validator.
	 */
	if (READ_ONCE(uwg->bbr_mode) == UWG_BBR_MODE_ON) {
		struct uwg_bbr *bbr;

		rcu_read_lock();
		bbr = uwg_peer_bbr_lookup(peer);
		if (bbr) {
			spin_lock_bh(&peer->bbr_lock);
			uwg_bbr_note_sent(bbr, keypair->internal_id,
					  PACKET_CB(skb)->nonce);
			spin_unlock_bh(&peer->bbr_lock);
		}
		rcu_read_unlock();
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

/*
 * Wakes a batch the cwnd gate parked. The emergency release has to be
 * retried by somebody: with every ACK lost and no fresh traffic nothing
 * would ever look at the queue again. The peer's keepalive timer already
 * runs exactly the staged-send path and stays silent while packets are
 * queued, so it is re-armed a few milliseconds out instead of adding a
 * second timer per peer.
 */
static void uwg_packet_cwnd_arm_retry(struct uwg_peer *peer)
{
	unsigned long delay = usecs_to_jiffies(UWG_TX_CWND_BLOCK_MAX_NS /
					       NSEC_PER_USEC);

	rcu_read_lock_bh();
	if (likely(netif_running(peer->device->dev) &&
		   !READ_ONCE(peer->is_dead)))
		mod_timer(&peer->timer_send_keepalive,
			  jiffies + max_t(unsigned long, 1, delay));
	rcu_read_unlock_bh();
}

static void uwg_packet_stage_head(struct uwg_peer *peer,
				  struct sk_buff_head *packets)
{
	if (skb_queue_empty(packets))
		return;
	spin_lock_bh(&peer->staged_packet_queue.lock);
	skb_queue_splice(packets, &peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);
}

/*
 * ACK-clocked congestion window gate.
 *
 * Returns false when the whole batch has to stay queued; it then sits in
 * `hold` in its original order. When only a prefix fits the remaining
 * allowance, the prefix is left in `packets` and the rest is moved to
 * `hold`, again in order, so the caller can put it back at the head of the
 * staged queue. Keepalives bypass the gate: parking them would stall the
 * very traffic that is supposed to reopen the window.
 *
 * The allowance is taken from uwg_bbr_cwnd_allowance(), i.e. from the
 * effective window (raw cwnd floored at one worst-case ACK interval of
 * pacing). Without that floor a low-RTT path would send its whole cwnd and
 * then sit idle until the next delayed-ACK burst, which is the sleep
 * ceiling this gate exists to avoid.
 *
 * The gate is armed only after uwg_bbr_full_bw_reached() and only while
 * uwg_bbr_loss_limited() holds: in STARTUP, and on a clean channel, the
 * pacer is the only limiter. See the comment on the activation check below.
 *
 * All the BBR state is read under bbr_lock through the rcu-protected
 * pointer, exactly like the neighbouring send/ACK accounting.
 */
static bool uwg_packet_cwnd_gate(struct uwg_peer *peer,
				 struct sk_buff_head *packets,
				 struct sk_buff_head *hold)
{
	struct uwg_bbr *bbr;
	struct sk_buff *skb;
	u64 allowance, used = 0, now_ns, blocked_ns;
	unsigned int keep = 0, qlen;
	bool arm_retry = false;

	__skb_queue_head_init(hold);

	if (READ_ONCE(peer->device->bbr_mode) != UWG_BBR_MODE_ON)
		return true;
	/* Control frames never enter this queue; keepalives do, and are what
	 * keeps a stalled tunnel alive.
	 */
	if (PACKET_CB(skb_peek(packets))->is_keepalive)
		return true;

	now_ns = ktime_get_ns();
	rcu_read_lock();
	bbr = uwg_peer_bbr_lookup(peer);
	if (unlikely(!bbr)) {
		rcu_read_unlock();
		return true;
	}
	spin_lock_bh(&peer->bbr_lock);
	/*
	 * The gate is armed only in the steady, loss-bound state:
	 *
	 *  - STARTUP must not be gated. There cwnd is 2 * BDP while the pacer
	 *    runs at a 2.77x gain, so the window is only marginally ahead of
	 *    the token bucket; withholding on it thins the ACK stream (the
	 *    peer acks in 8-16 packet bursts), which starves the bandwidth
	 *    estimate and keeps cwnd -- and with it the floor -- from growing.
	 *
	 *  - On a clean channel cwnd is not a limit, it is a guess: the path
	 *    is paced, not congestion-bound. Gating on it would let the ACK
	 *    cadence, not the path, set the ceiling.
	 *
	 * cwnd is the reaction to congestion. inflight_hi is initialised to
	 * U64_MAX and is only lowered by a loss cut, so inflight_hi < cwnd
	 * means a loss response has already set a bound below the window and
	 * withholding on it is the honest thing to do. Everything else stays
	 * pacer-driven.
	 */
	if (!uwg_bbr_full_bw_reached(bbr) || !uwg_bbr_loss_limited(bbr)) {
		peer->cwnd_blocked_ns = 0;
		spin_unlock_bh(&peer->bbr_lock);
		rcu_read_unlock();
		return true;
	}
	allowance = uwg_bbr_cwnd_allowance(bbr);
	blocked_ns = peer->cwnd_blocked_ns;
	/* Emergency release: the window did not reopen in time, most likely
	 * because the ACK stream is gone. Sending is better than a dead tunnel.
	 */
	if (blocked_ns && now_ns - blocked_ns >= UWG_TX_CWND_BLOCK_MAX_NS) {
		peer->cwnd_blocked_ns = 0;
		spin_unlock_bh(&peer->bbr_lock);
		rcu_read_unlock();
		net_dbg_ratelimited("%s: cwnd gate timed out for peer %llu, sending %u packet(s)\n",
				    peer->device->dev->name, peer->internal_id,
				    packets->qlen);
		return true;
	}
	spin_unlock_bh(&peer->bbr_lock);
	rcu_read_unlock();

	qlen = packets->qlen;
	skb_queue_walk(packets, skb) {
		/* Datagrams are charged with the same length uwg_bbr_on_send()
		 * accounts, so the gate and inflight stay in one unit.
		 */
		if (used + skb->len > allowance)
			break;
		used += skb->len;
		++keep;
	}

	if (!keep) {
		skb_queue_splice_tail_init(packets, hold);
		spin_lock_bh(&peer->bbr_lock);
		if (!peer->cwnd_blocked_ns) {
			peer->cwnd_blocked_ns = now_ns;
			arm_retry = true;
		}
		spin_unlock_bh(&peer->bbr_lock);
		if (arm_retry)
			uwg_packet_cwnd_arm_retry(peer);
		return false;
	}

	if (keep < qlen) {
		/* Move the tail over one skb at a time so `hold` keeps the
		 * original order for skb_queue_splice() back to the head.
		 */
		while (packets->qlen > keep) {
			skb = skb_dequeue_tail(packets);
			__skb_queue_head(hold, skb);
		}
		WRITE_ONCE(peer->cwnd_gate_ns, now_ns);
	}

	/* Something goes out: the next stall starts its own timeout. */
	spin_lock_bh(&peer->bbr_lock);
	peer->cwnd_blocked_ns = 0;
	spin_unlock_bh(&peer->bbr_lock);
	return true;
}

void uwg_packet_send_staged_packets(struct uwg_peer *peer)
{
	struct noise_keypair *keypair;
	struct sk_buff_head packets, hold;
	struct sk_buff *skb;

	__skb_queue_head_init(&hold);

	/* Steal the current queue into our local one. */
	__skb_queue_head_init(&packets);
	spin_lock_bh(&peer->staged_packet_queue.lock);
	skb_queue_splice_init(&peer->staged_packet_queue, &packets);
	spin_unlock_bh(&peer->staged_packet_queue.lock);
	if (unlikely(skb_queue_empty(&packets)))
		return;

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

	if (READ_ONCE(peer->device->bbr_mode) != UWG_BBR_MODE_OFF)
		uwg_peer_bbr_keypair_changed(peer, keypair->internal_id);

	/* The congestion window gates the batch before a single nonce is
	 * burned, so withheld packets keep their place in the queue. They are
	 * left with their socket owner intact: unlike the handshake wait in
	 * out_nokey, this is a short ACK-clocked pause, and the charged write
	 * memory is the backpressure the application should see.
	 */
	if (!uwg_packet_cwnd_gate(peer, &packets, &hold)) {
		uwg_packet_stage_head(peer, &hold);
		uwg_noise_keypair_put(keypair, false);
		return;
	}

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

	uwg_packet_bbr_on_send(peer, &packets, keypair->internal_id);

	packets.prev->next = NULL;
	uwg_peer_get(keypair->entry.peer);
	PACKET_CB(packets.next)->keypair = keypair;
	uwg_packet_create_data(peer, packets.next);
	/* The prefix is on its way, so the withheld tail can go back to the
	 * head of the staged queue without a concurrent sender overtaking the
	 * prefix. Order inside both lists is preserved.
	 */
	uwg_packet_stage_head(peer, &hold);
	return;

out_invalid:
	WRITE_ONCE(keypair->sending.is_valid, false);
out_nokey:
	uwg_noise_keypair_put(keypair, false);

	/* Restore the part the cwnd gate withheld behind the prefix, so the
	 * batch goes back as one ordered queue.
	 */
	skb_queue_splice_tail_init(&hold, &packets);

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
