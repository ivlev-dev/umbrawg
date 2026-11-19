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

#include <linux/uio.h>
#include <linux/inetdevice.h>
#include <linux/socket.h>
#include <linux/random.h>
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
#define UWG_TX_PACE_MAX_NS (2ULL * NSEC_PER_MSEC)

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
					      HANDSHAKE_DSCP, uwg->init_padding, true);
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
						      HANDSHAKE_DSCP,
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

static unsigned int calculate_skb_padding(struct sk_buff *skb)
{
	unsigned int padded_size, last_unit = skb->len;

	if (unlikely(!PACKET_CB(skb)->mtu))
		return ALIGN(last_unit, MESSAGE_PADDING_MULTIPLE) - last_unit;

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
	return padded_size - last_unit;
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
	unsigned int udp_window;
	int padding;
	u16_range_t content_padding_addition;

	padding = peer->device->transport_padding;
	content_padding_addition = peer->device->content_padding_addition;

	udp_window = padding + MESSAGE_MINIMUM_LENGTH + skb->len;
	if (READ_ONCE(peer->udp_window) < udp_window)
		WRITE_ONCE(peer->udp_window, udp_window);

	/* Force hash calculation before encryption so that flow analysis is
	 * consistent over the inner packet.
	 */
	skb_get_hash(skb);

	/* Calculate lengths. */
	packet_len = skb->len + MESSAGE_MINIMUM_LENGTH + padding;
	if (!u16_range_is_zero(content_padding_addition)) {
		padding_len = uwg_peer_skb_randomize_padding_addition(peer, peer->device, packet_len);
	} else if (peer->device->random_trailers) {
		padding_len = uwg_peer_skb_random_trailer(peer, peer->device, packet_len);
	} else {
		padding_len = calculate_skb_padding(skb);
	}

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
		skb_queue_tail(&peer->staged_packet_queue, skb);
		net_dbg_ratelimited("%s: Sending keepalive packet to peer %llu (%pISpfsc)\n",
				    peer->device->dev->name, peer->internal_id,
				    &peer->endpoint.addr);
	}

	uwg_packet_send_staged_packets(peer);
}

static void uwg_packet_bbr_on_send(struct uwg_peer *peer,
				   struct sk_buff_head *packets)
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
	skb_queue_walk(packets, skb) {
		if (PACKET_CB(skb)->is_keepalive)
			continue;
		uwg_bbr_on_send(bbr, PACKET_CB(skb)->nonce, skb->len, now_ns);
	}
	spin_unlock_bh(&peer->bbr_lock);
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
	u64 delay_ns;
	u32 delay_us;

	if (len < UWG_TX_PACE_MIN_BYTES)
		return;
	if (READ_ONCE(peer->device->bbr_mode) != UWG_BBR_MODE_ON)
		return;
	if (!preemptible())
		return;

	delay_ns = uwg_packet_pace_delay_ns(peer, len);
	if (delay_ns < NSEC_PER_USEC)
		return;
	delay_ns = min(delay_ns, UWG_TX_PACE_MAX_NS);
	delay_us = (u32)div_u64(delay_ns + NSEC_PER_USEC - 1, NSEC_PER_USEC);
	usleep_range(delay_us, delay_us + delay_us / 4 + 1);
}

static void uwg_packet_send_one(struct uwg_peer *peer, struct sk_buff *skb,
				bool *data_sent)
{
	bool is_keepalive = PACKET_CB(skb)->is_keepalive;
	u8 ds = PACKET_CB(skb)->ds;

	if (!is_keepalive)
		uwg_packet_pace(peer, skb->len);

	if (likely(!uwg_socket_send_skb_to_peer(peer, skb, ds) && !is_keepalive))
		*data_sent = true;
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

	for (i = 0; i < count; ++i) {
		keepalive |= PACKET_CB(pkts[i])->is_keepalive;
		kfree_skb(pkts[i]);
	}

	if (!keepalive)
		uwg_packet_pace(peer, count * len);

	if (likely(!uwg_socket_send_skb_to_peer(peer, agg, ds) && !keepalive))
		*data_sent = true;
	return true;
}

static void uwg_packet_create_data_done(struct uwg_peer *peer,
					struct sk_buff **entries,
					unsigned int entries_len)
{
	struct sk_buff *skbs[UWG_TX_MAX_SKBS];
	unsigned int nskbs = 0, i, j;
	bool data_sent = false;

	for (i = 0; i < entries_len; ++i) {
		struct sk_buff *skb, *next;

		skb_list_walk_safe(entries[i], skb, next) {
			skb_mark_not_on_list(skb);
			if (likely(nskbs < UWG_TX_MAX_SKBS)) {
				skbs[nskbs++] = skb;
			} else {
				uwg_packet_send_one(peer, skb, &data_sent);
			}
		}
	}

	uwg_timers_any_authenticated_packet_traversal(peer);
	uwg_timers_any_authenticated_packet_sent(peer);

	for (i = 0; i < nskbs; ) {
		unsigned int len = skbs[i]->len;
		u8 ds = PACKET_CB(skbs[i])->ds;

		j = i + 1;
		if (PACKET_CB(skbs[i])->is_fec)
			goto send_group;

		for (; j < nskbs; ++j) {
			if (skbs[j]->len != len ||
			    PACKET_CB(skbs[j])->ds != ds)
				break;
			if (PACKET_CB(skbs[j])->is_fec)
				break;
			if (j - i >= UWG_GSO_SEGS_MAX)
				break;
			if ((j - i + 1) * len > UWG_GSO_MAX_BYTES)
				break;
		}

send_group:
		if (j - i > 1 && uwg_packet_send_gso(peer, skbs + i, j - i,
						     &data_sent)) {
			i = j;
			continue;
		}

		for (; i < j; ++i)
			uwg_packet_send_one(peer, skbs[i], &data_sent);
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

void uwg_packet_send_staged_packets(struct uwg_peer *peer)
{
	struct noise_keypair *keypair;
	struct sk_buff_head packets;
	struct sk_buff *skb;

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
		PACKET_CB(skb)->nonce =
				atomic64_inc_return(&keypair->sending_counter) - 1;
		if (unlikely(PACKET_CB(skb)->nonce >= REJECT_AFTER_MESSAGES))
			goto out_invalid;
	}

	uwg_packet_bbr_on_send(peer, &packets);

	packets.prev->next = NULL;
	uwg_peer_get(keypair->entry.peer);
	PACKET_CB(packets.next)->keypair = keypair;
	uwg_packet_create_data(peer, packets.next);
	return;

out_invalid:
	WRITE_ONCE(keypair->sending.is_valid, false);
out_nokey:
	uwg_noise_keypair_put(keypair, false);

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
