// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "peer.h"
#include "device.h"
#include "queueing.h"
#include "timers.h"
#include "peerlookup.h"
#include "noise.h"
#include "bbr.h"
#include "fec_data.h"

#include <linux/kref.h>
#include <linux/ktime.h>
#include <linux/lockdep.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/slab.h>

static struct kmem_cache *peer_cache;
static atomic64_t peer_counter = ATOMIC64_INIT(0);

/*
 * The controller instance is owned by the peer and swapped under
 * device_update_lock. Readers only dereference it inside an RCU read-side
 * critical section, so a mode change can drop the old instance after
 * synchronize_net() without racing the send or the ACK path.
 */
struct uwg_bbr *uwg_peer_bbr_lookup(struct uwg_peer *peer)
{
	return rcu_dereference(peer->bbr);
}

/*
 * Called whenever the peer starts using a different keypair. A rekey
 * restarts the nonce space at zero, so the old send ring cannot be matched
 * against new ACKs/loss reports any more. The id is checked under the BBR
 * lock because several paths (tx worker, ext receive) may notice the same
 * keypair concurrently. Never called under device_update_lock.
 */
void uwg_peer_bbr_keypair_changed(struct uwg_peer *peer, u64 keypair_id)
{
	struct uwg_bbr *bbr;

	rcu_read_lock();
	bbr = uwg_peer_bbr_lookup(peer);
	if (bbr) {
		spin_lock_bh(&peer->bbr_lock);
		if (peer->bbr_keypair_id != keypair_id) {
			peer->bbr_keypair_id = keypair_id;
			uwg_bbr_new_epoch(bbr, keypair_id, ktime_get_ns());
		}
		spin_unlock_bh(&peer->bbr_lock);
	}
	rcu_read_unlock();
}

static struct uwg_bbr *uwg_peer_bbr_alloc(void)
{
	struct uwg_bbr *bbr = kvmalloc(sizeof(*bbr), GFP_KERNEL);

	if (unlikely(!bbr))
		return NULL;
	uwg_bbr_init(bbr, 0, UWG_BBR_DEFAULT_RTT_US);
	return bbr;
}

void uwg_peer_bbr_release(struct uwg_peer *peer)
{
	struct uwg_bbr *bbr = rcu_dereference_protected(peer->bbr, 1);

	if (!bbr)
		return;
	RCU_INIT_POINTER(peer->bbr, NULL);
	synchronize_net();
	kvfree(bbr);
}

int uwg_peer_bbr_sync(struct uwg_peer *peer)
{
	struct uwg_bbr *bbr;

	if (READ_ONCE(peer->device->bbr_mode) == UWG_BBR_MODE_OFF) {
		uwg_peer_bbr_release(peer);
		return 0;
	}
	if (rcu_access_pointer(peer->bbr))
		return 0;

	bbr = uwg_peer_bbr_alloc();
	if (unlikely(!bbr))
		return -ENOMEM;
	rcu_assign_pointer(peer->bbr, bbr);
	return 0;
}

int uwg_peer_bbr_sync_device(struct uwg_device *uwg)
{
	struct uwg_peer *peer;
	int ret = 0;

	lockdep_assert_held(&uwg->device_update_lock);

	list_for_each_entry(peer, &uwg->peer_list, peer_list) {
		if (unlikely(uwg_peer_bbr_sync(peer)))
			ret = -ENOMEM;
	}
	return ret;
}

struct uwg_peer *uwg_peer_create(struct uwg_device *uwg,
			       const u8 public_key[NOISE_PUBLIC_KEY_LEN],
			       const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN])
{
	struct uwg_peer *peer;
	int ret = -ENOMEM;

	lockdep_assert_held(&uwg->device_update_lock);

	if (uwg->num_peers >= MAX_PEERS_PER_DEVICE)
		return ERR_PTR(ret);

	peer = kmem_cache_zalloc(peer_cache, GFP_KERNEL);
	if (unlikely(!peer))
		return ERR_PTR(ret);
	if (unlikely(dst_cache_init(&peer->endpoint_cache, GFP_KERNEL)))
		goto err;
	WRITE_ONCE(peer->udp_window, DEFAULT_UDP_WINDOW);

	peer->device = uwg;
	spin_lock_init(&peer->bbr_lock);
	if (unlikely(uwg_peer_bbr_sync(peer)))
		goto err_dst;
	uwg_ext_peer_init(peer);
	if (unlikely(uwg_peer_fec_sync(peer)))
		goto err_fec;
	peer->cipher = UWG_CIPHER_CHACHA20POLY1305;
	uwg_noise_handshake_init(&peer->handshake, &uwg->static_identity,
				public_key, preshared_key, peer);
	peer->internal_id = atomic64_inc_return(&peer_counter);
	peer->serial_work_cpu = nr_cpumask_bits;
	uwg_cookie_init(&peer->latest_cookie);
	uwg_timers_init(peer);
	uwg_cookie_checker_precompute_peer_keys(peer);
	spin_lock_init(&peer->keypairs.keypair_update_lock);
	INIT_WORK(&peer->transmit_handshake_work, uwg_packet_handshake_send_worker);
	INIT_WORK(&peer->transmit_packet_work, uwg_packet_tx_worker);
	uwg_prev_queue_init(&peer->tx_queue);
	uwg_prev_queue_init(&peer->rx_queue);
	rwlock_init(&peer->endpoint_lock);
	kref_init(&peer->refcount);
	skb_queue_head_init(&peer->staged_packet_queue);
	uwg_peer_reset_last_sent_handshake(peer);
	set_bit(NAPI_STATE_NO_BUSY_POLL, &peer->napi.state);
	netif_napi_add(uwg->dev, &peer->napi, uwg_packet_rx_poll);
	napi_enable(&peer->napi);
	list_add_tail(&peer->peer_list, &uwg->peer_list);
	INIT_LIST_HEAD(&peer->allowedips_list);
	uwg_pubkey_hashtable_add(uwg->peer_hashtable, peer);
	++uwg->num_peers;
	pr_debug("%s: Peer %llu created\n", uwg->dev->name, peer->internal_id);
	return peer;

err_fec:
	uwg_peer_bbr_release(peer);
err_dst:
	dst_cache_destroy(&peer->endpoint_cache);
err:
	kmem_cache_free(peer_cache, peer);
	return ERR_PTR(ret);
}

struct uwg_peer *uwg_peer_get_maybe_zero(struct uwg_peer *peer)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_bh_held(),
			 "Taking peer reference without holding the RCU read lock");
	if (unlikely(!peer || !kref_get_unless_zero(&peer->refcount)))
		return NULL;
	return peer;
}

static void peer_make_dead(struct uwg_peer *peer)
{
	/* Remove from configuration-time lookup structures. */
	list_del_init(&peer->peer_list);
	uwg_allowedips_remove_by_peer(&peer->device->peer_allowedips, peer,
				     &peer->device->device_update_lock);
	uwg_pubkey_hashtable_remove(peer->device->peer_hashtable, peer);

	/* Mark as dead, so that we don't allow jumping contexts after. */
	WRITE_ONCE(peer->is_dead, true);

	/* The caller must now synchronize_net() for this to take effect. */
}

static void peer_remove_after_dead(struct uwg_peer *peer)
{
	WARN_ON(!peer->is_dead);

	/* No more keypairs can be created for this peer, since is_dead protects
	 * add_new_keypair, so we can now destroy existing ones.
	 */
	uwg_noise_keypairs_clear(&peer->keypairs);

	/* Destroy all ongoing timers that were in-flight at the beginning of
	 * this function.
	 */
	uwg_timers_stop(peer);

	/* The transition between packet encryption/decryption queues isn't
	 * guarded by is_dead, but each reference's life is strictly bounded by
	 * two generations: once for parallel crypto and once for serial
	 * ingestion, so we can simply flush twice, and be sure that we no
	 * longer have references inside these queues.
	 */

	/* a) For encrypt/decrypt. */
	flush_workqueue(peer->device->packet_crypt_wq);
	/* b.1) For send (but not receive, since that's napi). */
	flush_workqueue(peer->device->packet_crypt_wq);
	/* b.2.1) For receive (but not send, since that's wq). */
	napi_disable(&peer->napi);
	/* b.2.1) It's now safe to remove the napi struct, which must be done
	 * here from process context.
	 */
	netif_napi_del(&peer->napi);

	/* Ensure any workstructs we own (like transmit_handshake_work or
	 * clear_peer_work) no longer are in use.
	 */
	flush_workqueue(peer->device->handshake_send_wq);

	/* After the above flushes, a peer might still be active in a few
	 * different contexts: 1) from xmit(), before hitting is_dead and
	 * returning, 2) from uwg_packet_consume_data(), before hitting is_dead
	 * and returning, 3) from uwg_receive_handshake_packet() after a point
	 * where it has processed an incoming handshake packet, but where
	 * all calls to pass it off to timers fails because of is_dead. We won't
	 * have new references in (1) eventually, because we're removed from
	 * allowedips; we won't have new references in (2) eventually, because
	 * uwg_index_hashtable_lookup will always return NULL, since we removed
	 * all existing keypairs and no more can be created; we won't have new
	 * references in (3) eventually, because we're removed from the pubkey
	 * hash table, which allows for a maximum of one handshake response,
	 * via the still-uncleared index hashtable entry, but not more than one,
	 * and in uwg_cookie_message_consume, the lookup eventually gets a peer
	 * with a refcount of zero, so no new reference is taken.
	 */

	--peer->device->num_peers;
	uwg_peer_bbr_release(peer);
	uwg_peer_fec_release(peer);
	uwg_peer_put(peer);
}

/* We have a separate "remove" function make sure that all active places where
 * a peer is currently operating will eventually come to an end and not pass
 * their reference onto another context.
 */
void uwg_peer_remove(struct uwg_peer *peer)
{
	if (unlikely(!peer))
		return;
	lockdep_assert_held(&peer->device->device_update_lock);

	peer_make_dead(peer);
	synchronize_net();
	peer_remove_after_dead(peer);
}

void uwg_peer_remove_all(struct uwg_device *uwg)
{
	struct uwg_peer *peer, *temp;
	LIST_HEAD(dead_peers);

	lockdep_assert_held(&uwg->device_update_lock);

	/* Avoid having to traverse individually for each one. */
	uwg_allowedips_free(&uwg->peer_allowedips, &uwg->device_update_lock);

	list_for_each_entry_safe(peer, temp, &uwg->peer_list, peer_list) {
		peer_make_dead(peer);
		list_add_tail(&peer->peer_list, &dead_peers);
	}
	synchronize_net();
	list_for_each_entry_safe(peer, temp, &dead_peers, peer_list)
		peer_remove_after_dead(peer);
}

static void rcu_release(struct rcu_head *rcu)
{
	struct uwg_peer *peer = container_of(rcu, struct uwg_peer, rcu);

	dst_cache_destroy(&peer->endpoint_cache);
	WARN_ON(uwg_prev_queue_peek(&peer->tx_queue) || uwg_prev_queue_peek(&peer->rx_queue));

	/* The peer is normally released before the last reference is put;
	 * this covers a peer created but never fully removed.
	 */
	kfree(rcu_dereference_protected(peer->bbr, 1));
	uwg_peer_fec_rcu_free(peer);

	/* The final zeroing takes care of clearing any remaining handshake key
	 * material and other potentially sensitive information.
	 */
	memzero_explicit(peer, sizeof(*peer));
	kmem_cache_free(peer_cache, peer);
}

static void kref_release(struct kref *refcount)
{
	struct uwg_peer *peer = container_of(refcount, struct uwg_peer, refcount);

	pr_debug("%s: Peer %llu (%pISpfsc) destroyed\n",
		 peer->device->dev->name, peer->internal_id,
		 &peer->endpoint.addr);

	/* Remove ourself from dynamic runtime lookup structures, now that the
	 * last reference is gone.
	 */
	uwg_index_hashtable_remove(peer->device->index_hashtable,
				  &peer->handshake.entry);

	/* Remove any lingering packets that didn't have a chance to be
	 * transmitted.
	 */
	uwg_packet_purge_staged_packets(peer);

	/* Free the memory used. */
	call_rcu(&peer->rcu, rcu_release);
}

void uwg_peer_put(struct uwg_peer *peer)
{
	if (unlikely(!peer))
		return;
	kref_put(&peer->refcount, kref_release);
}

int __init uwg_peer_init(void)
{
	peer_cache = KMEM_CACHE(uwg_peer, 0);
	return peer_cache ? 0 : -ENOMEM;
}

void uwg_peer_uninit(void)
{
	kmem_cache_destroy(peer_cache);
}
