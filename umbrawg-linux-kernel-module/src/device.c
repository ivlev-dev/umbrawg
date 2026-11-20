// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "junk.h"
#include "queueing.h"
#include "socket.h"
#include "timers.h"
#include "device.h"
#include "ratelimiter.h"
#include "peer.h"
#include "messages.h"
#include "fec_data.h"

#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <linux/icmp.h>
#include <linux/suspend.h>
#include <net/dst_metadata.h>
#include <net/gso.h>
#include <net/icmp.h>
#include <net/rtnetlink.h>
#include <net/ip_tunnels.h>
#include <net/addrconf.h>

static LIST_HEAD(device_list);

static int uwg_open(struct net_device *dev)
{
	struct in_device *dev_v4 = __in_dev_get_rtnl(dev);
	struct inet6_dev *dev_v6 = __in6_dev_get(dev);
	struct uwg_device *uwg = netdev_priv(dev);
	struct uwg_peer *peer;
	int ret;

	if (dev_v4) {
		/* At some point we might put this check near the ip_rt_send_
		 * redirect call of ip_forward in net/ipv4/ip_forward.c, similar
		 * to the current secpath check.
		 */
		IN_DEV_CONF_SET(dev_v4, SEND_REDIRECTS, false);
		IPV4_DEVCONF_ALL(dev_net(dev), SEND_REDIRECTS) = false;
	}
	if (dev_v6)
		dev_v6->cnf.addr_gen_mode = IN6_ADDR_GEN_MODE_NONE;

	mutex_lock(&uwg->device_update_lock);
	ret = uwg_socket_init(uwg, uwg->incoming_port);
	if (ret < 0)
		goto out;
	list_for_each_entry(peer, &uwg->peer_list, peer_list) {
		uwg_packet_send_staged_packets(peer);
		if (peer->persistent_keepalive_interval)
			uwg_packet_send_keepalive(peer);
	}
out:
	mutex_unlock(&uwg->device_update_lock);
	return ret;
}

static int uwg_pm_notification(struct notifier_block *nb, unsigned long action, void *data)
{
	struct uwg_device *uwg;
	struct uwg_peer *peer;

	/* If the machine is constantly suspending and resuming, as part of
	 * its normal operation rather than as a somewhat rare event, then we
	 * don't actually want to clear keys.
	 */
	if (IS_ENABLED(CONFIG_PM_AUTOSLEEP) ||
	    IS_ENABLED(CONFIG_PM_USERSPACE_AUTOSLEEP))
		return 0;

	if (action != PM_HIBERNATION_PREPARE && action != PM_SUSPEND_PREPARE)
		return 0;

	rtnl_lock();
	list_for_each_entry(uwg, &device_list, device_list) {
		mutex_lock(&uwg->device_update_lock);
		list_for_each_entry(peer, &uwg->peer_list, peer_list) {
			timer_delete(&peer->timer_zero_key_material);
			uwg_noise_handshake_clear(&peer->handshake);
			uwg_noise_keypairs_clear(&peer->keypairs);
		}
		mutex_unlock(&uwg->device_update_lock);
	}
	rtnl_unlock();
	rcu_barrier();
	return 0;
}

static struct notifier_block pm_notifier = { .notifier_call = uwg_pm_notification };

static int uwg_vm_notification(struct notifier_block *nb, unsigned long action, void *data)
{
	struct uwg_device *uwg;
	struct uwg_peer *peer;

	rtnl_lock();
	list_for_each_entry(uwg, &device_list, device_list) {
		mutex_lock(&uwg->device_update_lock);
		list_for_each_entry(peer, &uwg->peer_list, peer_list)
			uwg_noise_expire_current_peer_keypairs(peer);
		mutex_unlock(&uwg->device_update_lock);
	}
	rtnl_unlock();
	return 0;
}

static struct notifier_block vm_notifier = { .notifier_call = uwg_vm_notification };

static int uwg_stop(struct net_device *dev)
{
	struct uwg_device *uwg = netdev_priv(dev);
	struct uwg_peer *peer;
	struct sk_buff *skb;

	mutex_lock(&uwg->device_update_lock);
	list_for_each_entry(peer, &uwg->peer_list, peer_list) {
		uwg_packet_purge_staged_packets(peer);
		uwg_timers_stop(peer);
		uwg_noise_handshake_clear(&peer->handshake);
		uwg_noise_keypairs_clear(&peer->keypairs);
		uwg_peer_reset_last_sent_handshake(peer);
	}
	mutex_unlock(&uwg->device_update_lock);
	while ((skb = ptr_ring_consume(&uwg->handshake_queue.ring)) != NULL)
		kfree_skb(skb);
	atomic_set(&uwg->handshake_queue_len, 0);
	uwg_socket_reinit(uwg, NULL, NULL);
	return 0;
}

static netdev_tx_t uwg_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct uwg_device *uwg = netdev_priv(dev);
	struct sk_buff_head packets;
	struct uwg_peer *peer;
	struct sk_buff *next;
	sa_family_t family;
	u32 mtu;
	int ret;

	if (unlikely(!uwg_check_packet_protocol(skb))) {
		ret = -EPROTONOSUPPORT;
		net_dbg_ratelimited("%s: Invalid IP packet\n", dev->name);
		goto err;
	}

	peer = uwg_allowedips_lookup_dst(&uwg->peer_allowedips, skb);
	if (unlikely(!peer)) {
		ret = -ENOKEY;
		if (skb->protocol == htons(ETH_P_IP))
			net_dbg_ratelimited("%s: No peer has allowed IPs matching %pI4\n",
					    dev->name, &ip_hdr(skb)->daddr);
		else if (skb->protocol == htons(ETH_P_IPV6))
			net_dbg_ratelimited("%s: No peer has allowed IPs matching %pI6\n",
					    dev->name, &ipv6_hdr(skb)->daddr);
		goto err_icmp;
	}

	family = READ_ONCE(peer->endpoint.addr.sa_family);
	if (unlikely(family != AF_INET && family != AF_INET6)) {
		ret = -EDESTADDRREQ;
		net_dbg_ratelimited("%s: No valid endpoint has been configured or discovered for peer %llu\n",
				    dev->name, peer->internal_id);
		goto err_peer;
	}

	mtu = skb_valid_dst(skb) ? dst_mtu(skb_dst(skb)) : dev->mtu;

	__skb_queue_head_init(&packets);
	if (!skb_is_gso(skb)) {
		skb_mark_not_on_list(skb);
	} else {
		struct sk_buff *segs = skb_gso_segment(skb, 0);

		if (IS_ERR(segs)) {
			ret = PTR_ERR(segs);
			goto err_peer;
		}
		dev_kfree_skb(skb);
		skb = segs;
	}

	skb_list_walk_safe(skb, skb, next) {
		skb_mark_not_on_list(skb);

		skb = skb_share_check(skb, GFP_ATOMIC);
		if (unlikely(!skb))
			continue;

		/* We only need to keep the original dst around for icmp,
		 * so at this point we're in a position to drop it.
		 */
		skb_dst_drop(skb);

		PACKET_CB(skb)->mtu = mtu;
		PACKET_CB(skb)->is_keepalive = false;
		PACKET_CB(skb)->is_fec = false;
		PACKET_CB(skb)->pace_len = 0;

		if (uwg_fec_tx_push(peer, skb, &packets))
			continue;

		__skb_queue_tail(&packets, skb);
	}

	spin_lock_bh(&peer->staged_packet_queue.lock);
	/* If the queue is getting too big, we start removing the oldest packets
	 * until it's small again. We do this before adding the new packet, so
	 * we don't remove GSO segments that are in excess.
	 */
	while (skb_queue_len(&peer->staged_packet_queue) > MAX_STAGED_PACKETS) {
		dev_kfree_skb(__skb_dequeue(&peer->staged_packet_queue));
		DEV_STATS_INC(dev, tx_dropped);
	}
	skb_queue_splice_tail(&packets, &peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);

	uwg_packet_send_staged_packets(peer);

	uwg_peer_put(peer);
	return NETDEV_TX_OK;

err_peer:
	uwg_peer_put(peer);
err_icmp:
	if (skb->protocol == htons(ETH_P_IP))
		icmp_ndo_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
	else if (skb->protocol == htons(ETH_P_IPV6))
		icmpv6_ndo_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_ADDR_UNREACH, 0);
err:
	DEV_STATS_INC(dev, tx_errors);
	kfree_skb(skb);
	return ret;
}

static const struct net_device_ops netdev_ops = {
	.ndo_open		= uwg_open,
	.ndo_stop		= uwg_stop,
	.ndo_start_xmit		= uwg_xmit,
};

static void uwg_destruct(struct net_device *dev)
{
	struct uwg_device *uwg = netdev_priv(dev);
	int i;

	rtnl_lock();
	list_del(&uwg->device_list);
	rtnl_unlock();
	mutex_lock(&uwg->device_update_lock);
	rcu_assign_pointer(uwg->creating_net, NULL);
	uwg->incoming_port = 0;
	uwg_socket_reinit(uwg, NULL, NULL);
	/* The final references are cleared in the below calls to destroy_workqueue. */
	uwg_peer_remove_all(uwg);
	destroy_workqueue(uwg->handshake_receive_wq);
	destroy_workqueue(uwg->handshake_send_wq);
	destroy_workqueue(uwg->packet_crypt_wq);
	for (i = 0; i < ARRAY_SIZE(uwg->ispecs); ++i)
		jp_spec_free(&uwg->ispecs[i]);
	uwg_packet_queue_free(&uwg->handshake_queue, true);
	uwg_packet_queue_free_percpu(&uwg->decrypt_queue, false);
	uwg_packet_queue_free_percpu(&uwg->encrypt_queue, false);
	rcu_barrier(); /* Wait for all the peers to be actually freed. */
	uwg_header_protection_release(uwg);
	uwg_ratelimiter_uninit();
	memzero_explicit(&uwg->static_identity, sizeof(uwg->static_identity));
	kvfree(uwg->index_hashtable);
	kvfree(uwg->peer_hashtable);
	mutex_unlock(&uwg->device_update_lock);

	pr_debug("%s: Interface destroyed\n", dev->name);
	free_netdev(dev);
}

static const struct device_type device_type = { .name = KBUILD_MODNAME };

static void uwg_setup(struct net_device *dev)
{
	struct uwg_device *uwg = netdev_priv(dev);
	enum { UWG_NETDEV_FEATURES = NETIF_F_HW_CSUM | NETIF_F_RXCSUM |
				    NETIF_F_SG | NETIF_F_GSO |
				    NETIF_F_GSO_SOFTWARE | NETIF_F_HIGHDMA };
	const int overhead = MESSAGE_MINIMUM_LENGTH + sizeof(struct udphdr) +
			     max(sizeof(struct ipv6hdr), sizeof(struct iphdr));

	dev->netdev_ops = &netdev_ops;
	dev->header_ops = &ip_tunnel_header_ops;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->needed_headroom = DATA_PACKET_HEAD_ROOM;
	dev->needed_tailroom = noise_encrypted_len(MESSAGE_PADDING_MULTIPLE);
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;
	dev->priv_flags |= IFF_NO_QUEUE;
	dev->lltx = true;
	dev->features |= UWG_NETDEV_FEATURES;
	dev->hw_features |= UWG_NETDEV_FEATURES;
	dev->hw_enc_features |= UWG_NETDEV_FEATURES;
	dev->mtu = ETH_DATA_LEN - overhead;
	dev->max_mtu = round_down(INT_MAX, MESSAGE_PADDING_MULTIPLE) - overhead;
	dev->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;

	SET_NETDEV_DEVTYPE(dev, &device_type);

	/* We need to keep the dst around in case of icmp replies. */
	netif_keep_dst(dev);

	netif_set_tso_max_size(dev, GSO_MAX_SIZE);

	memset(uwg, 0, sizeof(*uwg));
	uwg->dev = dev;
	uwg->extra_ports = UWG_EXTRA_PORTS_DEFAULT;
	uwg->bbr_mode = UWG_BBR_MODE_OFF;
	uwg->fec_mode = UWG_FEC_MODE_OFF;

	u32_range_init(&uwg->init_header, MESSAGE_HANDSHAKE_INITIATION, MESSAGE_HANDSHAKE_INITIATION);
	u32_range_init(&uwg->resp_header, MESSAGE_HANDSHAKE_RESPONSE, MESSAGE_HANDSHAKE_RESPONSE);
	u32_range_init(&uwg->cookie_header, MESSAGE_HANDSHAKE_COOKIE, MESSAGE_HANDSHAKE_COOKIE);
	u32_range_init(&uwg->transport_header, MESSAGE_DATA, MESSAGE_DATA);
}

static int uwg_newlink(struct net_device *dev,
		      struct rtnl_newlink_params *params,
		      struct netlink_ext_ack *extack)
{
	struct net *link_net = rtnl_newlink_link_net(params);
	struct uwg_device *uwg = netdev_priv(dev);
	int ret = -ENOMEM, i;

	rcu_assign_pointer(uwg->creating_net, link_net);
	init_rwsem(&uwg->static_identity.lock);
	mutex_init(&uwg->socket_update_lock);
	mutex_init(&uwg->device_update_lock);
	for (i = 0; i < ARRAY_SIZE(uwg->ispecs); ++i)
		mutex_init(&uwg->ispecs[i].lock);
	uwg_allowedips_init(&uwg->peer_allowedips);
	uwg_cookie_checker_init(&uwg->cookie_checker, uwg);
	INIT_LIST_HEAD(&uwg->peer_list);
	uwg->device_update_gen = 1;

	uwg->peer_hashtable = uwg_pubkey_hashtable_alloc();
	if (!uwg->peer_hashtable)
		return ret;

	uwg->index_hashtable = uwg_index_hashtable_alloc();
	if (!uwg->index_hashtable)
		goto err_free_peer_hashtable;

	uwg->handshake_receive_wq = alloc_workqueue("uwg-kex-%s",
			WQ_CPU_INTENSIVE | WQ_FREEZABLE | WQ_PERCPU, 0, dev->name);
	if (!uwg->handshake_receive_wq)
		goto err_free_index_hashtable;

	uwg->handshake_send_wq = alloc_workqueue("uwg-kex-%s",
			WQ_UNBOUND | WQ_FREEZABLE, 0, dev->name);
	if (!uwg->handshake_send_wq)
		goto err_destroy_handshake_receive;

	uwg->packet_crypt_wq = alloc_workqueue("uwg-crypt-%s",
			WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_PERCPU, 0, dev->name);
	if (!uwg->packet_crypt_wq)
		goto err_destroy_handshake_send;

	ret = uwg_packet_queue_init_percpu(&uwg->encrypt_queue,
					   uwg_packet_encrypt_worker,
					   MAX_QUEUED_PACKETS);
	if (ret < 0)
		goto err_destroy_packet_crypt;

	ret = uwg_packet_queue_init_percpu(&uwg->decrypt_queue,
					   uwg_packet_decrypt_worker,
					   MAX_QUEUED_PACKETS);
	if (ret < 0)
		goto err_free_encrypt_queue;

	ret = uwg_packet_queue_init(&uwg->handshake_queue, uwg_packet_handshake_receive_worker,
				   MAX_QUEUED_INCOMING_HANDSHAKES);
	if (ret < 0)
		goto err_free_decrypt_queue;

	ret = uwg_ratelimiter_init();
	if (ret < 0)
		goto err_free_handshake_queue;

	netif_threaded_enable(dev);
	ret = register_netdevice(dev);
	if (ret < 0)
		goto err_uninit_ratelimiter;

	list_add(&uwg->device_list, &device_list);

	/* We wait until the end to assign priv_destructor, so that
	 * register_netdevice doesn't call it for us if it fails.
	 */
	dev->priv_destructor = uwg_destruct;

	pr_debug("%s: Interface created\n", dev->name);
	return ret;

err_uninit_ratelimiter:
	uwg_ratelimiter_uninit();
err_free_handshake_queue:
	uwg_packet_queue_free(&uwg->handshake_queue, false);
err_free_decrypt_queue:
	uwg_packet_queue_free_percpu(&uwg->decrypt_queue, false);
err_free_encrypt_queue:
	uwg_packet_queue_free_percpu(&uwg->encrypt_queue, false);
err_destroy_packet_crypt:
	destroy_workqueue(uwg->packet_crypt_wq);
err_destroy_handshake_send:
	destroy_workqueue(uwg->handshake_send_wq);
err_destroy_handshake_receive:
	destroy_workqueue(uwg->handshake_receive_wq);
err_free_index_hashtable:
	kvfree(uwg->index_hashtable);
err_free_peer_hashtable:
	kvfree(uwg->peer_hashtable);
	return ret;
}

static struct rtnl_link_ops link_ops __read_mostly = {
	.kind			= KBUILD_MODNAME,
	.priv_size		= sizeof(struct uwg_device),
	.setup			= uwg_setup,
	.newlink		= uwg_newlink,
};

static void uwg_netns_pre_exit(struct net *net)
{
	struct uwg_device *uwg;
	struct uwg_peer *peer;

	rtnl_lock();
	list_for_each_entry(uwg, &device_list, device_list) {
		if (rcu_access_pointer(uwg->creating_net) == net) {
			pr_debug("%s: Creating namespace exiting\n", uwg->dev->name);
			netif_carrier_off(uwg->dev);
			mutex_lock(&uwg->device_update_lock);
			rcu_assign_pointer(uwg->creating_net, NULL);
			uwg_socket_reinit(uwg, NULL, NULL);
			list_for_each_entry(peer, &uwg->peer_list, peer_list)
				uwg_socket_clear_peer_endpoint_src(peer);
			mutex_unlock(&uwg->device_update_lock);
		}
	}
	rtnl_unlock();
}

static struct pernet_operations pernet_ops = {
	.pre_exit = uwg_netns_pre_exit
};

int __init uwg_device_init(void)
{
	int ret;

	ret = register_pm_notifier(&pm_notifier);
	if (ret)
		return ret;

	ret = register_random_vmfork_notifier(&vm_notifier);
	if (ret)
		goto error_pm;

	ret = register_pernet_device(&pernet_ops);
	if (ret)
		goto error_vm;

	ret = rtnl_link_register(&link_ops);
	if (ret)
		goto error_pernet;

	return 0;

error_pernet:
	unregister_pernet_device(&pernet_ops);
error_vm:
	unregister_random_vmfork_notifier(&vm_notifier);
error_pm:
	unregister_pm_notifier(&pm_notifier);
	return ret;
}

void uwg_device_uninit(void)
{
	rtnl_link_unregister(&link_ops);
	unregister_pernet_device(&pernet_ops);
	unregister_random_vmfork_notifier(&vm_notifier);
	unregister_pm_notifier(&pm_notifier);
	rcu_barrier();
}
