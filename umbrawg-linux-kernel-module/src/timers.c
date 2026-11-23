// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "timers.h"
#include "device.h"
#include "messages.h"
#include "peer.h"
#include "queueing.h"
#include "socket.h"
#include "type.h"

/*
 * - Timer for retransmitting the handshake if we don't hear back after
 * `REKEY_TIMEOUT + jitter` ms.
 *
 * - Timer for sending empty packet if we have received a packet but after have
 * not sent one for `KEEPALIVE_TIMEOUT` ms.
 *
 * - Timer for initiating new handshake if we have sent a packet but after have
 * not received one (even empty) for `(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) +
 * jitter` ms.
 *
 * - Timer for zeroing out all ephemeral keys after `(REJECT_AFTER_TIME * 3)` ms
 * if no new keys have been received.
 *
 * - Timer for, if enabled, sending an empty authenticated packet every user-
 * specified seconds.
 */

static inline void mod_peer_timer(struct uwg_peer *peer,
				  struct timer_list *timer,
				  unsigned long expires)
{
	rcu_read_lock_bh();
	if (likely(netif_running(peer->device->dev) &&
		   !READ_ONCE(peer->is_dead)))
		mod_timer(timer, expires);
	rcu_read_unlock_bh();
}

static void uwg_expired_retransmit_handshake(struct timer_list *timer)
{
	struct uwg_peer *peer = timer_container_of(peer, timer,
						  timer_retransmit_handshake);
	u16 timeout = !u16_range_is_zero(peer->device->rekey_after_time) ?
		u16_range_pick_one(peer->device->rekey_after_time) : REJECT_AFTER_TIME;

	if (peer->timer_handshake_attempts > peer->max_handshake_attempts) {
		pr_debug("%s: Handshake for peer %llu (%pISpfsc) did not complete after %d attempts, giving up\n",
			 peer->device->dev->name, peer->internal_id,
			 &peer->endpoint.addr, peer->max_handshake_attempts + 2);

		timer_delete(&peer->timer_send_keepalive);
		/* We drop all packets without a keypair and don't try again,
		 * if we try unsuccessfully for too long to make a handshake.
		 */
		uwg_packet_purge_staged_packets(peer);

		/* We set a timer for destroying any residue that might be left
		 * of a partial exchange.
		 */
		if (!timer_pending(&peer->timer_zero_key_material))
			mod_peer_timer(peer, &peer->timer_zero_key_material,
				       jiffies + timeout * 3 * HZ);
	} else {
		++peer->timer_handshake_attempts;
		pr_debug("%s: Handshake for peer %llu (%pISpfsc) did not complete after %d seconds, retrying (try %d)\n",
			 peer->device->dev->name, peer->internal_id,
			 &peer->endpoint.addr, (int)REKEY_TIMEOUT,
			 peer->timer_handshake_attempts + 1);

		/* We clear the endpoint address src address, in case this is
		 * the cause of trouble.
		 */
		uwg_socket_clear_peer_endpoint_src(peer);

		uwg_packet_send_queued_handshake_initiation(peer, true);
	}
}

static void uwg_expired_send_keepalive(struct timer_list *timer)
{
	struct uwg_peer *peer = timer_container_of(peer, timer,
						  timer_send_keepalive);
	u16 timeout = !u16_range_is_zero(peer->device->keepalive_timeout) ?
		u16_range_pick_one(peer->device->keepalive_timeout) : KEEPALIVE_TIMEOUT;

	/* A keepalive is only needed when the peer has heard from us after the
	 * window was armed. Sending data (or another keepalive) in the window
	 * already proved liveness, so the expiry is silent in that case. The
	 * timer then stays armed as long as traffic keeps arriving
	 * (timer_need_another_keepalive), which is what allows the send path
	 * to skip the timer_delete() it used to do on every batch.
	 *
	 * A non-empty staged queue always takes the call: the cwnd gate parks a
	 * batch here and re-arms this very timer to retry it, and
	 * uwg_packet_send_keepalive() then only drains that queue.
	 */
	if (!skb_queue_empty_lockless(&peer->staged_packet_queue) ||
	    !time_after(peer->last_data_tx, peer->keepalive_armed))
		uwg_packet_send_keepalive(peer);
	if (peer->timer_need_another_keepalive) {
		peer->timer_need_another_keepalive = false;
		peer->keepalive_armed = jiffies;
		mod_peer_timer(peer, &peer->timer_send_keepalive,
			       jiffies + timeout * HZ);
	} else {
		peer->keepalive_armed = 0;
	}
}

static void uwg_expired_new_handshake(struct timer_list *timer)
{
	struct uwg_peer *peer = timer_container_of(peer, timer,
						  timer_new_handshake);

	pr_debug("%s: Retrying handshake with peer %llu (%pISpfsc) because we stopped hearing back after %d seconds\n",
		 peer->device->dev->name, peer->internal_id,
		 &peer->endpoint.addr, (int)(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT));
	/* We clear the endpoint address src address, in case this is the cause
	 * of trouble.
	 */
	uwg_socket_clear_peer_endpoint_src(peer);
	uwg_packet_send_queued_handshake_initiation(peer, false);
}

static void uwg_expired_zero_key_material(struct timer_list *timer)
{
	struct uwg_peer *peer = timer_container_of(peer, timer,
						  timer_zero_key_material);

	rcu_read_lock_bh();
	if (!READ_ONCE(peer->is_dead)) {
		uwg_peer_get(peer);
		if (!queue_work(peer->device->handshake_send_wq,
				&peer->clear_peer_work))
			/* If the work was already on the queue, we want to drop
			 * the extra reference.
			 */
			uwg_peer_put(peer);
	}
	rcu_read_unlock_bh();
}

static void uwg_queued_expired_zero_key_material(struct work_struct *work)
{
	struct uwg_peer *peer = container_of(work, struct uwg_peer,
					    clear_peer_work);

	pr_debug("%s: Zeroing out all keys for peer %llu (%pISpfsc), since we haven't received a new one in %d seconds\n",
		 peer->device->dev->name, peer->internal_id,
		 &peer->endpoint.addr, (int)REJECT_AFTER_TIME * 3);
	uwg_noise_handshake_clear(&peer->handshake);
	uwg_noise_keypairs_clear(&peer->keypairs);
	uwg_peer_put(peer);
}

static void uwg_expired_send_persistent_keepalive(struct timer_list *timer)
{
	struct uwg_peer *peer = timer_container_of(peer, timer,
						  timer_persistent_keepalive);

	if (likely(peer->persistent_keepalive_interval))
		uwg_packet_send_keepalive(peer);
}

static void uwg_expired_send_ack(struct timer_list *timer)
{
	struct uwg_peer *peer = timer_container_of(peer, timer,
						  timer_send_ack);

	uwg_ext_ack_timeout(peer);
}

/* Should be called after an authenticated data packet is sent. */
void uwg_timers_data_sent(struct uwg_peer *peer)
{
	u16 keepalive_timeout = !u16_range_is_zero(peer->device->keepalive_timeout) ?
		u16_range_hi(peer->device->keepalive_timeout) : KEEPALIVE_TIMEOUT,
		rekey_timeout = !u16_range_is_zero(peer->device->rekey_timeout) ?
		u16_range_pick_one(peer->device->rekey_timeout) : REKEY_TIMEOUT;

	peer->last_data_tx = jiffies;
	if (!timer_pending(&peer->timer_new_handshake))
		mod_peer_timer(peer, &peer->timer_new_handshake,
			jiffies + (keepalive_timeout + rekey_timeout) * HZ +
			get_random_u32_below(REKEY_TIMEOUT_JITTER_MAX_JIFFIES));
}

/* Should be called after an authenticated data packet is received. */
void uwg_timers_data_received(struct uwg_peer *peer)
{
	u16 timeout = !u16_range_is_zero(peer->device->keepalive_timeout) ?
		u16_range_pick_one(peer->device->keepalive_timeout) : KEEPALIVE_TIMEOUT;

	if (likely(netif_running(peer->device->dev))) {
		if (!timer_pending(&peer->timer_send_keepalive)) {
			peer->keepalive_armed = jiffies;
			mod_peer_timer(peer, &peer->timer_send_keepalive,
				       jiffies + timeout * HZ);
		} else {
			peer->timer_need_another_keepalive = true;
		}
	}
}

/* Should be called after any type of authenticated packet is sent, whether
 * keepalive, data, or handshake.
 *
 * This used to be timer_delete(): a timer-base lock per batch, and because the
 * next received packet then saw an unarmed timer, a mod_timer per data packet.
 * The timer is now left armed and the expiry compares last_data_tx with the
 * moment the window was armed; only frames recorded by uwg_timers_data_sent()
 * count as liveness, so a downlink that only ACKs sends no keepalives while an
 * idle downlink still sends one per keepalive_timeout. See
 * uwg_expired_send_keepalive().
 */
void uwg_timers_any_authenticated_packet_sent(struct uwg_peer *peer)
{
	/* Nothing to do: last_data_tx is recorded by uwg_timers_data_sent()
	 * only for real frames, and the keepalive timer is left armed. See
	 * the comment on uwg_expired_send_keepalive().
	 */
}

/* Should be called after any type of authenticated packet is received, whether
 * keepalive, data, or handshake.
 */
void uwg_timers_any_authenticated_packet_received(struct uwg_peer *peer)
{
	timer_delete(&peer->timer_new_handshake);
}

/* Should be called after a handshake initiation message is sent. */
void uwg_timers_handshake_initiated(struct uwg_peer *peer)
{
	u16 timeout = !u16_range_is_zero(peer->device->rekey_timeout) ?
		u16_range_pick_one(peer->device->rekey_timeout) : REKEY_TIMEOUT;

	mod_peer_timer(peer, &peer->timer_retransmit_handshake,
		       jiffies + timeout * HZ +
		       get_random_u32_below(REKEY_TIMEOUT_JITTER_MAX_JIFFIES));
}

/* Should be called after a handshake response message is received and processed
 * or when getting key confirmation via the first data message.
 */
void uwg_timers_handshake_complete(struct uwg_peer *peer)
{
	timer_delete(&peer->timer_retransmit_handshake);
	peer->timer_handshake_attempts = 0;
	peer->max_handshake_attempts = !u16_range_is_zero(peer->device->max_handshake_attempts) ? u16_range_pick_one(peer->device->max_handshake_attempts) : MAX_TIMER_HANDSHAKES;
	peer->sent_lastminute_handshake = false;
	ktime_get_real_ts64(&peer->walltime_last_handshake);
}

/* Should be called after an ephemeral key is created, which is before sending a
 * handshake response or after receiving a handshake response.
 */
void uwg_timers_session_derived(struct uwg_peer *peer)
{
	u16 timeout = !u16_range_is_zero(peer->device->reject_after_time) ?
		u16_range_pick_one(peer->device->reject_after_time) : REJECT_AFTER_TIME;

	mod_peer_timer(peer, &peer->timer_zero_key_material,
		       jiffies + timeout * 3 * HZ);
}

/* Should be called before a packet with authentication, whether
 * keepalive, data, or handshakem is sent, or after one is received.
 */
void uwg_timers_any_authenticated_packet_traversal(struct uwg_peer *peer)
{
	if (!u16_range_is_zero(peer->persistent_keepalive_interval))
		mod_peer_timer(peer, &peer->timer_persistent_keepalive,
			jiffies + u16_range_pick_one(peer->persistent_keepalive_interval) * HZ);
}

void uwg_timers_init(struct uwg_peer *peer)
{
	timer_setup(&peer->timer_retransmit_handshake,
		    uwg_expired_retransmit_handshake, 0);
	timer_setup(&peer->timer_send_keepalive, uwg_expired_send_keepalive, 0);
	timer_setup(&peer->timer_new_handshake, uwg_expired_new_handshake, 0);
	timer_setup(&peer->timer_zero_key_material,
		    uwg_expired_zero_key_material, 0);
	timer_setup(&peer->timer_persistent_keepalive,
		    uwg_expired_send_persistent_keepalive, 0);
	timer_setup(&peer->timer_send_ack, uwg_expired_send_ack, 0);
	INIT_WORK(&peer->clear_peer_work, uwg_queued_expired_zero_key_material);
	peer->timer_handshake_attempts = 0;
	peer->max_handshake_attempts = !u16_range_is_zero(peer->device->max_handshake_attempts) ? u16_range_pick_one(peer->device->max_handshake_attempts) : MAX_TIMER_HANDSHAKES;
	peer->sent_lastminute_handshake = false;
	peer->timer_need_another_keepalive = false;
}

/* Arm the delayed-ACK timer with the same guard as mod_peer_timer().
 * uwg_ext_ack_armed() runs from the NAPI poll (and from the ACK timer
 * callback itself), so it can race with peer teardown; timer_reduce() has no
 * is_dead/netif_running check of its own and would re-arm a timer after
 * uwg_timers_stop() has already returned.
 */
void uwg_timers_ack_reduce(struct uwg_peer *peer, unsigned long expires)
{
	rcu_read_lock_bh();
	if (likely(netif_running(peer->device->dev) &&
		   !READ_ONCE(peer->is_dead)))
		timer_reduce(&peer->timer_send_ack, expires);
	rcu_read_unlock_bh();
}

void uwg_timers_stop(struct uwg_peer *peer)
{
	timer_delete_sync(&peer->timer_retransmit_handshake);
	timer_delete_sync(&peer->timer_send_keepalive);
	timer_delete_sync(&peer->timer_new_handshake);
	timer_delete_sync(&peer->timer_zero_key_material);
	timer_delete_sync(&peer->timer_persistent_keepalive);
	timer_delete_sync(&peer->timer_send_ack);
	flush_work(&peer->clear_peer_work);
}

/* Final peer teardown. The caller has already marked the peer dead and run
 * synchronize_net() (uwg_peer_remove()/uwg_peer_remove_all()), so no RCU/NAPI
 * reader can pass the is_dead check in mod_peer_timer() or
 * uwg_timers_ack_reduce() and arm a timer any more. timer_shutdown_sync()
 * additionally poisons the timers, which matters because the peer is freed
 * later from an RCU callback: a late arm would otherwise target freed memory.
 *
 * uwg_stop() must keep using uwg_timers_stop(): the netdev can be brought
 * back up and the timers must remain usable for a restart.
 */
void uwg_timers_shutdown(struct uwg_peer *peer)
{
	timer_shutdown_sync(&peer->timer_retransmit_handshake);
	timer_shutdown_sync(&peer->timer_send_keepalive);
	timer_shutdown_sync(&peer->timer_new_handshake);
	timer_shutdown_sync(&peer->timer_zero_key_material);
	timer_shutdown_sync(&peer->timer_persistent_keepalive);
	timer_shutdown_sync(&peer->timer_send_ack);
	flush_work(&peer->clear_peer_work);
}
