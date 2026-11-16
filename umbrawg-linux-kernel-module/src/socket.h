/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _UWG_SOCKET_H
#define _UWG_SOCKET_H

#include <linux/netdevice.h>
#include <linux/udp.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>

int uwg_socket_init(struct uwg_device *uwg, u16 port);
void uwg_socket_reinit(struct uwg_device *uwg, struct sock *new4,
		      struct sock *new6);
int uwg_socket_send_buffer_to_peer(struct uwg_peer *peer, void *data,
				  size_t len, u8 ds, size_t padding, bool trailer);
int uwg_socket_send_skb_to_peer(struct uwg_peer *peer, struct sk_buff *skb,
			       u8 ds);
int uwg_socket_send_buffer_as_reply_to_skb(struct uwg_device *uwg,
					  struct sk_buff *in_skb,
					  void *out_buffer, size_t len, size_t padding);

int uwg_socket_endpoint_from_skb(struct endpoint *endpoint,
				const struct sk_buff *skb);
void uwg_socket_set_peer_endpoint(struct uwg_peer *peer,
				 const struct endpoint *endpoint);
void uwg_socket_set_peer_endpoint_from_skb(struct uwg_peer *peer,
					  const struct sk_buff *skb);
void uwg_socket_clear_peer_endpoint_src(struct uwg_peer *peer);

#if defined(CONFIG_DYNAMIC_DEBUG) || defined(DEBUG)
#define net_dbg_skb_ratelimited(fmt, dev, skb, ...) do {                       \
		struct endpoint __endpoint;                                    \
		uwg_socket_endpoint_from_skb(&__endpoint, skb);                 \
		net_dbg_ratelimited(fmt, dev, &__endpoint.addr,                \
				    ##__VA_ARGS__);                            \
	} while (0)
#else
#define net_dbg_skb_ratelimited(fmt, skb, ...)
#endif

#endif /* _UWG_SOCKET_H */
