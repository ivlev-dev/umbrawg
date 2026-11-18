// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "netlink.h"
#include "device.h"
#include "header_protection.h"
#include "peer.h"
#include "socket.h"
#include "queueing.h"
#include "messages.h"
#include "type.h"
#include "uapi/umbrawg.h"
#include <linux/if.h>
#include <net/genetlink.h>
#include <net/sock.h>
#include <crypto/utils.h>
#include <linux/random.h>
#include <linux/bitops.h>

#include <linux/inet.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/inetdevice.h>
#include <linux/byteorder/generic.h>

int bogus_endpoints = 0;
char *bogus_endpoints_prefix = "127.0.0.0/8";
char *bogus_endpoints_prefix6 = "ff80::/16";

static struct genl_family genl_family;

static const struct nla_policy device_policy[UWGDEVICE_A_MAX + 1] = {
	[UWGDEVICE_A_IFINDEX]		= { .type = NLA_U32 },
	[UWGDEVICE_A_IFNAME]		= { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[UWGDEVICE_A_PRIVATE_KEY]	= NLA_POLICY_EXACT_LEN(NOISE_PUBLIC_KEY_LEN),
	[UWGDEVICE_A_PUBLIC_KEY]		= NLA_POLICY_EXACT_LEN(NOISE_PUBLIC_KEY_LEN),
	[UWGDEVICE_A_FLAGS]		= NLA_POLICY_MASK(NLA_U32, __UWGDEVICE_F_ALL),
	[UWGDEVICE_A_LISTEN_PORT]	= { .type = NLA_U16 },
	[UWGDEVICE_A_FWMARK]		= { .type = NLA_U32 },
	[UWGDEVICE_A_PEERS]		= { .type = NLA_NESTED },
	[UWGDEVICE_A_JC]		= { .type = NLA_U16 },
	[UWGDEVICE_A_JMIN]		= { .type = NLA_U16 },
	[UWGDEVICE_A_JMAX]		= { .type = NLA_U16 },
	[UWGDEVICE_A_S1]		= { .type = NLA_U16 },
	[UWGDEVICE_A_S2]		= { .type = NLA_U16 },
	[UWGDEVICE_A_H1]		= { .type = NLA_U64 },
	[UWGDEVICE_A_H2]		= { .type = NLA_U64 },
	[UWGDEVICE_A_H3]		= { .type = NLA_U64 },
	[UWGDEVICE_A_H4]		= { .type = NLA_U64 },
	[UWGDEVICE_A_PEER]	= { .type = NLA_NESTED },
	[UWGDEVICE_A_S3]		= { .type = NLA_U16 },
	[UWGDEVICE_A_S4]		= { .type = NLA_U16 },
	[UWGDEVICE_A_I1]		= { .type = NLA_NUL_STRING },
	[UWGDEVICE_A_I2]		= { .type = NLA_NUL_STRING },
	[UWGDEVICE_A_I3]		= { .type = NLA_NUL_STRING },
	[UWGDEVICE_A_I4]		= { .type = NLA_NUL_STRING },
	[UWGDEVICE_A_I5]		= { .type = NLA_NUL_STRING },
	[UWGDEVICE_A_HEADER_PROTECTION_KEY] = NLA_POLICY_EXACT_LEN(HEADER_PROTECTION_KEY_SIZE),
	[UWGDEVICE_A_CONTENT_PADDING_ADDITION] = { .type = NLA_U32 },
	[UWGDEVICE_A_REKEY_AFTER_TIME] = { .type = NLA_U32 },
	[UWGDEVICE_A_REKEY_TIMEOUT] = { .type = NLA_U32 },
	[UWGDEVICE_A_REJECT_AFTER_TIME] = { .type = NLA_U32 },
	[UWGDEVICE_A_KEEPALIVE_TIMEOUT] = { .type = NLA_U32 },
	[UWGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS] = { .type = NLA_U32 },
	[UWGDEVICE_A_RANDOM_TRAILERS] = { .type = NLA_U8 },
	[UWGDEVICE_A_DISABLE_COOKIES] = { .type = NLA_U8 },
};

static const struct nla_policy peer_policy[UWGPEER_A_MAX + 1] = {
	[UWGPEER_A_PUBLIC_KEY]				= NLA_POLICY_EXACT_LEN(NOISE_PUBLIC_KEY_LEN),
	[UWGPEER_A_PRESHARED_KEY]			= NLA_POLICY_EXACT_LEN(NOISE_SYMMETRIC_KEY_LEN),
	[UWGPEER_A_FLAGS]				= NLA_POLICY_MASK(NLA_U32, __UWGPEER_F_ALL),
	[UWGPEER_A_ENDPOINT]				= NLA_POLICY_MIN_LEN(sizeof(struct sockaddr)),
	[UWGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]	= { .type = NLA_U32 },
	[UWGPEER_A_LAST_HANDSHAKE_TIME]			= NLA_POLICY_EXACT_LEN(sizeof(struct __kernel_timespec)),
	[UWGPEER_A_RX_BYTES]				= { .type = NLA_U64 },
	[UWGPEER_A_TX_BYTES]				= { .type = NLA_U64 },
	[UWGPEER_A_ALLOWEDIPS]				= { .type = NLA_NESTED },
	[UWGPEER_A_PROTOCOL_VERSION]			= { .type = NLA_U32 },
	[UWGPEER_A_ADVANCED_SECURITY]    		= { .type = NLA_FLAG },
	[UWGPEER_A_CIPHER]				= { .type = NLA_U32 }
};

static const struct nla_policy allowedip_policy[UWGALLOWEDIP_A_MAX + 1] = {
	[UWGALLOWEDIP_A_FAMILY]		= { .type = NLA_U16 },
	[UWGALLOWEDIP_A_IPADDR]		= NLA_POLICY_MIN_LEN(sizeof(struct in_addr)),
	[UWGALLOWEDIP_A_CIDR_MASK]	= { .type = NLA_U8 },
	[UWGALLOWEDIP_A_FLAGS]		= NLA_POLICY_MASK(NLA_U32, __UWGALLOWEDIP_F_ALL),
};

static struct uwg_device *lookup_interface(struct nlattr **attrs,
					  struct sk_buff *skb)
{
	struct net_device *dev = NULL;

	if (!attrs[UWGDEVICE_A_IFINDEX] == !attrs[UWGDEVICE_A_IFNAME])
		return ERR_PTR(-EBADR);
	if (attrs[UWGDEVICE_A_IFINDEX])
		dev = dev_get_by_index(sock_net(skb->sk),
				       nla_get_u32(attrs[UWGDEVICE_A_IFINDEX]));
	else if (attrs[UWGDEVICE_A_IFNAME])
		dev = dev_get_by_name(sock_net(skb->sk),
				      nla_data(attrs[UWGDEVICE_A_IFNAME]));
	if (!dev)
		return ERR_PTR(-ENODEV);
	if (!dev->rtnl_link_ops || !dev->rtnl_link_ops->kind ||
	    strcmp(dev->rtnl_link_ops->kind, KBUILD_MODNAME)) {
		dev_put(dev);
		return ERR_PTR(-EOPNOTSUPP);
	}
	return netdev_priv(dev);
}

static int get_allowedips(struct sk_buff *skb, const u8 *ip, u8 cidr,
			  int family)
{
	struct nlattr *allowedip_nest;

	allowedip_nest = nla_nest_start(skb, 0);
	if (!allowedip_nest)
		return -EMSGSIZE;

	if (nla_put_u8(skb, UWGALLOWEDIP_A_CIDR_MASK, cidr) ||
	    nla_put_u16(skb, UWGALLOWEDIP_A_FAMILY, family) ||
	    nla_put(skb, UWGALLOWEDIP_A_IPADDR, family == AF_INET6 ?
		    sizeof(struct in6_addr) : sizeof(struct in_addr), ip)) {
		nla_nest_cancel(skb, allowedip_nest);
		return -EMSGSIZE;
	}

	nla_nest_end(skb, allowedip_nest);
	return 0;
}

struct dump_ctx {
	struct uwg_device *uwg;
	struct uwg_peer *next_peer;
	u64 allowedips_seq;
	struct allowedips_node *next_allowedip;
};

#define DUMP_CTX(cb) ((struct dump_ctx *)(cb)->args)

struct ipv4_prefix {
	__be32 prefix;
	int prefix_len;
};

struct ipv6_prefix {
	u8 prefix[16];
	int prefix_len;
};

static inline int parse_ipv4_prefix(const char *prefix_str, struct ipv4_prefix *prefix)
{
	char addr_str[INET_ADDRSTRLEN];
	const char *slash;
	int ret;
	u8 addr[4];

	if (!prefix_str || !prefix)
		return -EINVAL;

	slash = strchr(prefix_str, '/');
	if (!slash)
		return -EINVAL;

	if (slash - prefix_str >= INET_ADDRSTRLEN)
		return -EINVAL;

	// strscpy count includes null terminator
	strscpy(addr_str, prefix_str, slash - prefix_str + 1);

	ret = kstrtoint(slash + 1, 10, &prefix->prefix_len);
	if (ret < 0)
		return ret;

	if (prefix->prefix_len < 0 || prefix->prefix_len > 32)
		return -EINVAL;

	ret = in4_pton(addr_str, -1, addr, '\0', NULL);
	if (ret != 1)
		return -EINVAL;

	prefix->prefix = *(__be32 *)addr;

	return 0;
}

static inline int generate_ipv4_address_with_prefix(const struct ipv4_prefix *prefix, __be32 *addr)
{
	u32 prefix_host_order, random_suffix, full_addr_host_order;
	u32 suffix_mask;

	if (!prefix || !addr)
		return -EINVAL;

	prefix_host_order = ntohl(prefix->prefix);

	if (prefix->prefix_len == 32) {
		suffix_mask = 0;
	} else {
		suffix_mask = (1U << (32 - prefix->prefix_len)) - 1;
	}

	get_random_bytes(&random_suffix, sizeof(random_suffix));
	random_suffix &= suffix_mask;
	full_addr_host_order = (prefix_host_order & (~suffix_mask)) | random_suffix;
	*addr = htonl(full_addr_host_order);

	return 0;
}

static inline int parse_ipv6_prefix(const char *prefix_str, struct ipv6_prefix *prefix)
{
	char addr_str[INET6_ADDRSTRLEN];
	const char *slash;
	int ret;

	if (!prefix_str || !prefix)
		return -EINVAL;

	slash = strchr(prefix_str, '/');
	if (!slash)
		return -EINVAL;

	if (slash - prefix_str >= INET6_ADDRSTRLEN)
		return -EINVAL;

	// strscpy count includes null terminator
	strscpy(addr_str, prefix_str, slash - prefix_str + 1);

	ret = kstrtoint(slash + 1, 10, &prefix->prefix_len);
	if (ret < 0)
		return ret;

	if (prefix->prefix_len < 0 || prefix->prefix_len > 128)
		return -EINVAL;

	ret = in6_pton(addr_str, -1, prefix->prefix, '\0', NULL);
	if (ret != 1)
		return -EINVAL;

	return 0;
}

static inline int generate_ipv6_address_with_prefix(const struct ipv6_prefix *prefix, u8 *addr)
{
	int prefix_bytes, prefix_bits;
	u8 mask, random_byte;

	if (!prefix || !addr)
		return -EINVAL;

	memcpy(addr, prefix->prefix, 16);

	prefix_bytes = prefix->prefix_len / 8;
	prefix_bits = prefix->prefix_len % 8;

	if (prefix_bytes < 16) {
		get_random_bytes(addr + prefix_bytes, 16 - prefix_bytes);

		if (prefix_bits != 0) {
			get_random_bytes(&random_byte, sizeof(random_byte));
			mask = (u8)(0xFF << (8 - prefix_bits));
			addr[prefix_bytes] &= mask;
			addr[prefix_bytes] |= random_byte & ~mask;
		}
	}

	return 0;
}

static int
get_peer(struct uwg_peer *peer, struct sk_buff *skb, struct dump_ctx *ctx)
{

	struct nlattr *allowedips_nest, *peer_nest = nla_nest_start(skb, 0);
	struct allowedips_node *allowedips_node = ctx->next_allowedip;
	struct ipv4_prefix prefix;
	struct ipv6_prefix prefix6;
	bool fail;
	int ret;

	if (!peer_nest)
		return -EMSGSIZE;

	if (bogus_endpoints) {
		ret = parse_ipv4_prefix(bogus_endpoints_prefix, &prefix);
		if (ret < 0)
			return ret;

		ret = parse_ipv6_prefix(bogus_endpoints_prefix6, &prefix6);
		if (ret < 0)
			return ret;
	}

	fail = nla_put_u32(skb, UWGPEER_A_FLAGS, UWGPEER_F_HAS_ADVANCED_SECURITY);
	if (fail)
		goto err;

	down_read(&peer->handshake.lock);
	fail = nla_put(skb, UWGPEER_A_PUBLIC_KEY, NOISE_PUBLIC_KEY_LEN,
		       peer->handshake.remote_static);
	up_read(&peer->handshake.lock);
	if (fail)
		goto err;

	if (!allowedips_node) {
		const struct __kernel_timespec last_handshake = {
			.tv_sec = peer->walltime_last_handshake.tv_sec,
			.tv_nsec = peer->walltime_last_handshake.tv_nsec
		};

		down_read(&peer->handshake.lock);
		fail = nla_put(skb, UWGPEER_A_PRESHARED_KEY,
			       NOISE_SYMMETRIC_KEY_LEN,
			       peer->handshake.preshared_key);
		up_read(&peer->handshake.lock);
		if (fail)
			goto err;

		if (nla_put(skb, UWGPEER_A_LAST_HANDSHAKE_TIME,
			    sizeof(last_handshake), &last_handshake) ||
		    nla_put_u32(skb, UWGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
				peer->persistent_keepalive_interval) ||
		    nla_put_u64_64bit(skb, UWGPEER_A_TX_BYTES, peer->tx_bytes,
				      UWGPEER_A_UNSPEC) ||
		    nla_put_u64_64bit(skb, UWGPEER_A_RX_BYTES, peer->rx_bytes,
				      UWGPEER_A_UNSPEC) ||
		    nla_put_u32(skb, UWGPEER_A_PROTOCOL_VERSION, 1) ||
		    nla_put_u32(skb, UWGPEER_A_CIPHER, peer->cipher))
			goto err;

#ifndef OMIT_ENDPOINTS
		read_lock_bh(&peer->endpoint_lock);
		if (peer->endpoint.addr.sa_family == AF_INET) {
			struct sockaddr_in addr4 = peer->endpoint.addr4;

			if (bogus_endpoints) {
				ret = generate_ipv4_address_with_prefix(&prefix, &addr4.sin_addr.s_addr);
				if (ret < 0)
					goto err;
			}

			fail = nla_put(skb, UWGPEER_A_ENDPOINT, sizeof(addr4), &addr4);
		} else if (peer->endpoint.addr.sa_family == AF_INET6) {
			struct sockaddr_in6 addr6 = peer->endpoint.addr6;

			if (bogus_endpoints) {
				ret = generate_ipv6_address_with_prefix(&prefix6, addr6.sin6_addr.s6_addr);
				if (ret < 0)
					goto err;
			}

			fail = nla_put(skb, UWGPEER_A_ENDPOINT, sizeof(addr6), &addr6);
		}
		read_unlock_bh(&peer->endpoint_lock);
		if (fail)
			goto err;
#endif
		allowedips_node =
			list_first_entry_or_null(&peer->allowedips_list,
					struct allowedips_node, peer_list);
	}
	if (!allowedips_node)
		goto no_allowedips;
	if (!ctx->allowedips_seq)
		ctx->allowedips_seq = ctx->uwg->peer_allowedips.seq;
	else if (ctx->allowedips_seq != ctx->uwg->peer_allowedips.seq)
		goto no_allowedips;

	allowedips_nest = nla_nest_start(skb, UWGPEER_A_ALLOWEDIPS);
	if (!allowedips_nest)
		goto err;

	list_for_each_entry_from(allowedips_node, &peer->allowedips_list,
				 peer_list) {
		u8 cidr, ip[16] __aligned(__alignof(u64));
		int family;

		family = uwg_allowedips_read_node(allowedips_node, ip, &cidr);
		if (get_allowedips(skb, ip, cidr, family)) {
			nla_nest_end(skb, allowedips_nest);
			nla_nest_end(skb, peer_nest);
			ctx->next_allowedip = allowedips_node;
			return -EMSGSIZE;
		}
	}
	nla_nest_end(skb, allowedips_nest);
no_allowedips:
	nla_nest_end(skb, peer_nest);
	ctx->next_allowedip = NULL;
	ctx->allowedips_seq = 0;
	return 0;
err:
	nla_nest_cancel(skb, peer_nest);
	return -EMSGSIZE;
}

static int uwg_get_device_start(struct netlink_callback *cb)
{
	struct uwg_device *uwg;

	uwg = lookup_interface(genl_info_dump(cb)->attrs, cb->skb);
	if (IS_ERR(uwg))
		return PTR_ERR(uwg);
	DUMP_CTX(cb)->uwg = uwg;
	return 0;
}

static int uwg_get_device_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct uwg_peer *peer, *next_peer_cursor;
	struct dump_ctx *ctx = DUMP_CTX(cb);
	struct uwg_device *uwg = ctx->uwg;
	struct nlattr *peers_nest;
	int ret = -EMSGSIZE;
	bool done = true;
	void *hdr;
	char buf[32];

	rtnl_lock();
	mutex_lock(&uwg->device_update_lock);
	cb->seq = uwg->device_update_gen;
	next_peer_cursor = ctx->next_peer;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			  &genl_family, NLM_F_MULTI, UWG_CMD_GET_DEVICE);
	if (!hdr)
		goto out;
	genl_dump_check_consistent(cb, hdr);

	if (!ctx->next_peer) {
		if (nla_put_u16(skb, UWGDEVICE_A_LISTEN_PORT,
				uwg->incoming_port) ||
		    nla_put_u32(skb, UWGDEVICE_A_FWMARK, uwg->fwmark) ||
		    nla_put_u32(skb, UWGDEVICE_A_IFINDEX, uwg->dev->ifindex) ||
		    nla_put_string(skb, UWGDEVICE_A_IFNAME, uwg->dev->name) ||
		    nla_put_u16(skb, UWGDEVICE_A_JC, uwg->jc) ||
		    nla_put_u16(skb, UWGDEVICE_A_JMIN, uwg->jmin) ||
		    nla_put_u16(skb, UWGDEVICE_A_JMAX, uwg->jmax) ||
		    nla_put_u16(skb, UWGDEVICE_A_S1, uwg->init_padding) ||
		    nla_put_u16(skb, UWGDEVICE_A_S2,uwg->resp_padding) ||
			nla_put_u16(skb, UWGDEVICE_A_S3, uwg->cookie_padding) ||
			nla_put_u16(skb, UWGDEVICE_A_S4, uwg->transport_padding) ||
		    nla_put(skb, UWGDEVICE_A_H1, sizeof(u64), &uwg->init_header) ||
			nla_put(skb, UWGDEVICE_A_H2, sizeof(u64), &uwg->resp_header) ||
			nla_put(skb, UWGDEVICE_A_H3, sizeof(u64), &uwg->cookie_header) ||
			nla_put(skb, UWGDEVICE_A_H4, sizeof(u64), &uwg->transport_header) ||
			nla_put_u32(skb, UWGDEVICE_A_CONTENT_PADDING_ADDITION, uwg->content_padding_addition) ||
			nla_put_u32(skb, UWGDEVICE_A_REKEY_AFTER_TIME, uwg->rekey_after_time) ||
			nla_put_u32(skb, UWGDEVICE_A_REKEY_TIMEOUT, uwg->rekey_timeout) ||
			nla_put_u32(skb, UWGDEVICE_A_REJECT_AFTER_TIME, uwg->reject_after_time) ||
			nla_put_u32(skb, UWGDEVICE_A_KEEPALIVE_TIMEOUT, uwg->keepalive_timeout) ||
			nla_put_u32(skb, UWGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS, uwg->max_handshake_attempts) ||
			nla_put_u8(skb, UWGDEVICE_A_RANDOM_TRAILERS, uwg->random_trailers) ||
			nla_put_u8(skb, UWGDEVICE_A_DISABLE_COOKIES, uwg->disable_cookies))
			goto out;

		if ((uwg->ispecs[0].desc &&
				nla_put_string(skb, UWGDEVICE_A_I1, uwg->ispecs[0].desc)) ||
			(uwg->ispecs[1].desc &&
				nla_put_string(skb, UWGDEVICE_A_I2, uwg->ispecs[1].desc)) ||
			(uwg->ispecs[2].desc &&
				nla_put_string(skb, UWGDEVICE_A_I3, uwg->ispecs[2].desc)) ||
			(uwg->ispecs[3].desc &&
				nla_put_string(skb, UWGDEVICE_A_I4, uwg->ispecs[3].desc)) ||
			(uwg->ispecs[4].desc &&
				nla_put_string(skb, UWGDEVICE_A_I5, uwg->ispecs[4].desc)))
			goto out;

		down_read(&uwg->header_protection.lock);
		if (uwg->header_protection.has_protection) {
			uwg_header_protection_get_key(&uwg->header_protection, buf);
			if (nla_put(skb, UWGDEVICE_A_HEADER_PROTECTION_KEY, HEADER_PROTECTION_KEY_SIZE, buf)) {
				up_read(&uwg->header_protection.lock);
				goto out;
			}
		}
		up_read(&uwg->header_protection.lock);

		down_read(&uwg->static_identity.lock);
		if (uwg->static_identity.has_identity) {
			if (nla_put(skb, UWGDEVICE_A_PRIVATE_KEY,
				    NOISE_PUBLIC_KEY_LEN,
				    uwg->static_identity.static_private) ||
			    nla_put(skb, UWGDEVICE_A_PUBLIC_KEY,
				    NOISE_PUBLIC_KEY_LEN,
				    uwg->static_identity.static_public)) {
				up_read(&uwg->static_identity.lock);
				goto out;
			}
		}
		up_read(&uwg->static_identity.lock);
	}

	peers_nest = nla_nest_start(skb, UWGDEVICE_A_PEERS);
	if (!peers_nest)
		goto out;
	ret = 0;
	lockdep_assert_held(&uwg->device_update_lock);
	/* If the last cursor was removed in peer_remove or peer_remove_all, then
	 * we just treat this the same as there being no more peers left. The
	 * reason is that seq_nr should indicate to userspace that this isn't a
	 * coherent dump anyway, so they'll try again.
	 */
	if (list_empty(&uwg->peer_list) ||
	    (ctx->next_peer && ctx->next_peer->is_dead)) {
		nla_nest_cancel(skb, peers_nest);
		goto out;
	}
	peer = list_prepare_entry(ctx->next_peer, &uwg->peer_list, peer_list);
	list_for_each_entry_continue(peer, &uwg->peer_list, peer_list) {
		if (get_peer(peer, skb, ctx)) {
			done = false;
			break;
		}
		next_peer_cursor = peer;
	}
	nla_nest_end(skb, peers_nest);

out:
	if (!ret && !done && next_peer_cursor)
		uwg_peer_get(next_peer_cursor);
	uwg_peer_put(ctx->next_peer);
	mutex_unlock(&uwg->device_update_lock);
	rtnl_unlock();

	if (ret) {
		genlmsg_cancel(skb, hdr);
		return ret;
	}
	genlmsg_end(skb, hdr);
	if (done) {
		ctx->next_peer = NULL;
		return 0;
	}
	ctx->next_peer = next_peer_cursor;
	return skb->len;

	/* At this point, we can't really deal ourselves with safely zeroing out
	 * the private key material after usage. This will need an additional API
	 * in the kernel for marking skbs as zero_on_free.
	 */
}

static int uwg_get_device_done(struct netlink_callback *cb)
{
	struct dump_ctx *ctx = DUMP_CTX(cb);

	if (ctx->uwg)
		dev_put(ctx->uwg->dev);
	uwg_peer_put(ctx->next_peer);
	return 0;
}

static int set_port(struct uwg_device *uwg, u16 port)
{
	struct uwg_peer *peer;

	if (uwg->incoming_port == port)
		return 0;
	list_for_each_entry(peer, &uwg->peer_list, peer_list)
		uwg_socket_clear_peer_endpoint_src(peer);
	if (!netif_running(uwg->dev)) {
		uwg->incoming_port = port;
		return 0;
	}
	return uwg_socket_init(uwg, port);
}

static int set_allowedip(struct uwg_peer *peer, struct nlattr **attrs)
{
	int ret = -EINVAL;
	u32 flags = 0;
	u16 family;
	u8 cidr;

	if (!attrs[UWGALLOWEDIP_A_FAMILY] || !attrs[UWGALLOWEDIP_A_IPADDR] ||
	    !attrs[UWGALLOWEDIP_A_CIDR_MASK])
		return ret;
	family = nla_get_u16(attrs[UWGALLOWEDIP_A_FAMILY]);
	cidr = nla_get_u8(attrs[UWGALLOWEDIP_A_CIDR_MASK]);
	if (attrs[UWGALLOWEDIP_A_FLAGS])
		flags = nla_get_u32(attrs[UWGALLOWEDIP_A_FLAGS]);

	if (family == AF_INET && cidr <= 32 &&
	    nla_len(attrs[UWGALLOWEDIP_A_IPADDR]) == sizeof(struct in_addr)) {
		if (flags & UWGALLOWEDIP_F_REMOVE_ME)
			ret = uwg_allowedips_remove_v4(&peer->device->peer_allowedips,
						      nla_data(attrs[UWGALLOWEDIP_A_IPADDR]), cidr,
						      peer, &peer->device->device_update_lock);
		else
			ret = uwg_allowedips_insert_v4(&peer->device->peer_allowedips,
						      nla_data(attrs[UWGALLOWEDIP_A_IPADDR]), cidr,
						      peer, &peer->device->device_update_lock);
	} else if (family == AF_INET6 && cidr <= 128 &&
		   nla_len(attrs[UWGALLOWEDIP_A_IPADDR]) == sizeof(struct in6_addr)) {
		if (flags & UWGALLOWEDIP_F_REMOVE_ME)
			ret = uwg_allowedips_remove_v6(&peer->device->peer_allowedips,
						      nla_data(attrs[UWGALLOWEDIP_A_IPADDR]), cidr,
						      peer, &peer->device->device_update_lock);
		else
			ret = uwg_allowedips_insert_v6(&peer->device->peer_allowedips,
						      nla_data(attrs[UWGALLOWEDIP_A_IPADDR]), cidr,
						      peer, &peer->device->device_update_lock);
	}

	return ret;
}

static int set_peer(struct uwg_device *uwg, struct nlattr **attrs)
{
	u8 *public_key = NULL, *preshared_key = NULL;
	struct uwg_peer *peer = NULL;
	u32 flags = 0;
	int ret;

	ret = -EINVAL;
	if (attrs[UWGPEER_A_PUBLIC_KEY] &&
	    nla_len(attrs[UWGPEER_A_PUBLIC_KEY]) == NOISE_PUBLIC_KEY_LEN)
		public_key = nla_data(attrs[UWGPEER_A_PUBLIC_KEY]);
	else
		goto out;
	if (attrs[UWGPEER_A_PRESHARED_KEY] &&
	    nla_len(attrs[UWGPEER_A_PRESHARED_KEY]) == NOISE_SYMMETRIC_KEY_LEN)
		preshared_key = nla_data(attrs[UWGPEER_A_PRESHARED_KEY]);

	if (attrs[UWGPEER_A_FLAGS])
		flags = nla_get_u32(attrs[UWGPEER_A_FLAGS]);

	ret = -EPFNOSUPPORT;
	if (attrs[UWGPEER_A_PROTOCOL_VERSION]) {
		if (nla_get_u32(attrs[UWGPEER_A_PROTOCOL_VERSION]) != 1)
			goto out;
	}

	if (attrs[UWGPEER_A_CIPHER] &&
	    nla_get_u32(attrs[UWGPEER_A_CIPHER]) > UWG_CIPHER_AES256GCM) {
		ret = -EINVAL;
		goto out;
	}

	peer = uwg_pubkey_hashtable_lookup(uwg->peer_hashtable,
					  nla_data(attrs[UWGPEER_A_PUBLIC_KEY]));
	ret = 0;
	if (!peer) { /* Peer doesn't exist yet. Add a new one. */
		if (flags & (UWGPEER_F_REMOVE_ME | UWGPEER_F_UPDATE_ONLY))
			goto out;

		/* The peer is new, so there aren't allowed IPs to remove. */
		flags &= ~UWGPEER_F_REPLACE_ALLOWEDIPS;

		down_read(&uwg->static_identity.lock);
		if (uwg->static_identity.has_identity &&
		    !memcmp(nla_data(attrs[UWGPEER_A_PUBLIC_KEY]),
			    uwg->static_identity.static_public,
			    NOISE_PUBLIC_KEY_LEN)) {
			/* We silently ignore peers that have the same public
			 * key as the device. The reason we do it silently is
			 * that we'd like for people to be able to reuse the
			 * same set of API calls across peers.
			 */
			up_read(&uwg->static_identity.lock);
			ret = 0;
			goto out;
		}
		up_read(&uwg->static_identity.lock);

		peer = uwg_peer_create(uwg, public_key, preshared_key);
		if (IS_ERR(peer)) {
			ret = PTR_ERR(peer);
			peer = NULL;
			goto out;
		}
		/* Take additional reference, as though we've just been
		 * looked up.
		 */
		uwg_peer_get(peer);
	}

	if (flags & UWGPEER_F_REMOVE_ME) {
		uwg_peer_remove(peer);
		goto out;
	}

	if (attrs[UWGPEER_A_CIPHER])
		peer->cipher = nla_get_u32(attrs[UWGPEER_A_CIPHER]);

	if (preshared_key) {
		down_write(&peer->handshake.lock);
		memcpy(&peer->handshake.preshared_key, preshared_key,
		       NOISE_SYMMETRIC_KEY_LEN);
		up_write(&peer->handshake.lock);
	}

	if (attrs[UWGPEER_A_ENDPOINT]) {
		struct sockaddr *addr = nla_data(attrs[UWGPEER_A_ENDPOINT]);
		size_t len = nla_len(attrs[UWGPEER_A_ENDPOINT]);
		struct endpoint endpoint = { { { 0 } } };

		if (len == sizeof(struct sockaddr_in) && addr->sa_family == AF_INET) {
			endpoint.addr4 = *(struct sockaddr_in *)addr;
			uwg_socket_set_peer_endpoint(peer, &endpoint);
		} else if (len == sizeof(struct sockaddr_in6) && addr->sa_family == AF_INET6) {
			endpoint.addr6 = *(struct sockaddr_in6 *)addr;
			uwg_socket_set_peer_endpoint(peer, &endpoint);
		}
	}

	if (flags & UWGPEER_F_REPLACE_ALLOWEDIPS)
		uwg_allowedips_remove_by_peer(&uwg->peer_allowedips, peer,
					     &uwg->device_update_lock);

	if (attrs[UWGPEER_A_ALLOWEDIPS]) {
		struct nlattr *attr, *allowedip[UWGALLOWEDIP_A_MAX + 1];
		int rem;

		nla_for_each_nested(attr, attrs[UWGPEER_A_ALLOWEDIPS], rem) {
			ret = nla_parse_nested(allowedip, UWGALLOWEDIP_A_MAX,
					       attr, allowedip_policy, NULL);
			if (ret < 0)
				goto out;
			ret = set_allowedip(peer, allowedip);
			if (ret < 0)
				goto out;
		}
	}

	if (attrs[UWGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]) {
		const u16_range_t persistent_keepalive_interval = nla_get_u32(
				attrs[UWGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]);
		if (persistent_keepalive_interval &&
		    u16_range_lo(persistent_keepalive_interval) >
			    u16_range_hi(persistent_keepalive_interval)) {
			ret = -EINVAL;
			goto out;
		}
		const bool send_keepalive =
			u16_range_is_zero(peer->persistent_keepalive_interval) &&
			!u16_range_is_zero(persistent_keepalive_interval) &&
			netif_running(uwg->dev);

		peer->persistent_keepalive_interval = persistent_keepalive_interval;
		if (send_keepalive)
			uwg_packet_send_keepalive(peer);
	}

	if (netif_running(uwg->dev))
		uwg_packet_send_staged_packets(peer);

out:
	uwg_peer_put(peer);
	if (attrs[UWGPEER_A_PRESHARED_KEY])
		memzero_explicit(nla_data(attrs[UWGPEER_A_PRESHARED_KEY]),
				 nla_len(attrs[UWGPEER_A_PRESHARED_KEY]));
	return ret;
}

static int uwg_set_device(struct sk_buff *skb, struct genl_info *info)
{
	struct uwg_device *uwg = lookup_interface(info->attrs, skb);
	u32_range_t init_header, resp_header, cookie_header, transport_header;
	u32 flags = 0;
	int ret;
	u16 val16;
	bool has_protection;

	if (IS_ERR(uwg)) {
		ret = PTR_ERR(uwg);
		goto out_nodev;
	}

	rtnl_lock();
	mutex_lock(&uwg->device_update_lock);

	has_protection = uwg->header_protection.has_protection ||
		info->attrs[UWGDEVICE_A_HEADER_PROTECTION_KEY];

	if (info->attrs[UWGDEVICE_A_FLAGS])
		flags = nla_get_u32(info->attrs[UWGDEVICE_A_FLAGS]);

	if (info->attrs[UWGDEVICE_A_LISTEN_PORT] || info->attrs[UWGDEVICE_A_FWMARK]) {
		struct net *net;
		rcu_read_lock();
		net = rcu_dereference(uwg->creating_net);
		ret = !net || !ns_capable(net->user_ns, CAP_NET_ADMIN) ? -EPERM : 0;
		rcu_read_unlock();
		if (ret)
			goto out;
	}

	++uwg->device_update_gen;

	if (info->attrs[UWGDEVICE_A_FWMARK]) {
		struct uwg_peer *peer;

		uwg->fwmark = nla_get_u32(info->attrs[UWGDEVICE_A_FWMARK]);
		list_for_each_entry(peer, &uwg->peer_list, peer_list)
			uwg_socket_clear_peer_endpoint_src(peer);
	}

	if (info->attrs[UWGDEVICE_A_LISTEN_PORT]) {
		ret = set_port(uwg,
			nla_get_u16(info->attrs[UWGDEVICE_A_LISTEN_PORT]));
		if (ret)
			goto out;
	}

	if (info->attrs[UWGDEVICE_A_JC] ||
	    info->attrs[UWGDEVICE_A_JMIN] ||
	    info->attrs[UWGDEVICE_A_JMAX]) {
		u16 new_jc = info->attrs[UWGDEVICE_A_JC] ?
			nla_get_u16(info->attrs[UWGDEVICE_A_JC]) : uwg->jc;
		u16 new_jmin = info->attrs[UWGDEVICE_A_JMIN] ?
			nla_get_u16(info->attrs[UWGDEVICE_A_JMIN]) : uwg->jmin;
		u16 new_jmax = info->attrs[UWGDEVICE_A_JMAX] ?
			nla_get_u16(info->attrs[UWGDEVICE_A_JMAX]) : uwg->jmax;
		if (new_jmin > new_jmax) {
			net_dbg_ratelimited("%s: Jmin must not be greater than Jmax\n",
					uwg->dev->name);
			ret = -EINVAL;
			goto out;
		}
		if (info->attrs[UWGDEVICE_A_JC])
			uwg->jc = new_jc;
		if (info->attrs[UWGDEVICE_A_JMIN])
			uwg->jmin = new_jmin;
		if (info->attrs[UWGDEVICE_A_JMAX])
			uwg->jmax = new_jmax;
	}

	if (info->attrs[UWGDEVICE_A_S1]) {
		val16 = nla_get_u16(info->attrs[UWGDEVICE_A_S1]);
		if (has_protection && val16 < HEADER_PROTECTION_NONCE_SIZE) {
			net_dbg_ratelimited(
				"%s: S1 must be more then %d to use headerProtection\n",
				uwg->dev->name, HEADER_PROTECTION_NONCE_SIZE);
			ret = -EINVAL;
			goto out;
		}
		uwg->init_padding = val16;
	}

	if (info->attrs[UWGDEVICE_A_S2]) {
		val16 = nla_get_u16(info->attrs[UWGDEVICE_A_S2]);
		if (has_protection && val16 < HEADER_PROTECTION_NONCE_SIZE) {
			net_dbg_ratelimited(
				"%s: S2 must be more then %d to use headerProtection\n",
				uwg->dev->name, HEADER_PROTECTION_NONCE_SIZE);
			ret = -EINVAL;
			goto out;
		}
		uwg->resp_padding = val16;
	}

	if (info->attrs[UWGDEVICE_A_S3]) {
		val16 = nla_get_u16(info->attrs[UWGDEVICE_A_S3]);
		if (has_protection && val16 < HEADER_PROTECTION_NONCE_SIZE) {
			net_dbg_ratelimited(
				"%s: S3 must be more then %d to use headerProtection\n",
				uwg->dev->name, HEADER_PROTECTION_NONCE_SIZE);
			ret = -EINVAL;
			goto out;
		}
		uwg->cookie_padding = val16;
	}

	if (info->attrs[UWGDEVICE_A_S4]) {
		val16 = nla_get_u16(info->attrs[UWGDEVICE_A_S4]);
		if (has_protection && val16 < HEADER_PROTECTION_NONCE_SIZE) {
			net_dbg_ratelimited(
				"%s: S4 must be more then %d to use headerProtection\n",
				uwg->dev->name, HEADER_PROTECTION_NONCE_SIZE);
			ret = -EINVAL;
			goto out;
		}
		uwg->transport_padding = val16;
	}

	init_header = info->attrs[UWGDEVICE_A_H1] ?
		nla_get_u64(info->attrs[UWGDEVICE_A_H1]) : uwg->init_header;
	resp_header = info->attrs[UWGDEVICE_A_H2] ?
		nla_get_u64(info->attrs[UWGDEVICE_A_H2]) : uwg->resp_header;
	cookie_header = info->attrs[UWGDEVICE_A_H3] ?
		nla_get_u64(info->attrs[UWGDEVICE_A_H3]) : uwg->cookie_header;
	transport_header = info->attrs[UWGDEVICE_A_H4] ?
		nla_get_u64(info->attrs[UWGDEVICE_A_H4]) : uwg->transport_header;

	if (info->attrs[UWGDEVICE_A_H1]) {
		if (u32_range_overlap(init_header, resp_header) ||
			u32_range_overlap(init_header, cookie_header) ||
				u32_range_overlap(init_header, transport_header)) {
			net_dbg_ratelimited("%s: H1 must not overlap with others\n",
				uwg->dev->name);
			ret = -EINVAL;
			goto out;
		}
		uwg->init_header = init_header;
	}

	if (info->attrs[UWGDEVICE_A_H2]) {
		if (u32_range_overlap(resp_header, init_header) ||
			u32_range_overlap(resp_header, cookie_header) ||
				u32_range_overlap(resp_header, transport_header)) {
			net_dbg_ratelimited("%s: H2 must not overlap with others\n",
				uwg->dev->name);
			ret = -EINVAL;
			goto out;
		}
		uwg->resp_header = resp_header;
	}

	if (info->attrs[UWGDEVICE_A_H3]) {
		if (u32_range_overlap(cookie_header, init_header) ||
			u32_range_overlap(cookie_header, resp_header) ||
				u32_range_overlap(cookie_header, transport_header)) {
			net_dbg_ratelimited("%s: H3 must not overlap with others\n",
				uwg->dev->name);
			ret = -EINVAL;
			goto out;
		}
		uwg->cookie_header = cookie_header;
	}

	if (info->attrs[UWGDEVICE_A_H4]) {
		if (u32_range_overlap(transport_header, init_header) ||
			u32_range_overlap(transport_header, resp_header) ||
				u32_range_overlap(transport_header, cookie_header)) {
			net_dbg_ratelimited("%s: H4 must not overlap with others\n",
				uwg->dev->name);
			ret = -EINVAL;
			goto out;
		}
		uwg->transport_header = transport_header;
	}

	if (info->attrs[UWGDEVICE_A_I1]) {
		ret = jp_spec_setup(&uwg->ispecs[0], nla_data(info->attrs[UWGDEVICE_A_I1]));
		if (ret) {
			net_dbg_ratelimited("%s: I1-packet invalid format\n", uwg->dev->name);
			goto out;
		}
	}

	if (info->attrs[UWGDEVICE_A_I2]) {
		ret = jp_spec_setup(&uwg->ispecs[1], nla_data(info->attrs[UWGDEVICE_A_I2]));
		if (ret) {
			net_dbg_ratelimited("%s: I2-packet invalid format\n", uwg->dev->name);
			goto out;
		}
	}

	if (info->attrs[UWGDEVICE_A_I3]) {
		ret = jp_spec_setup(&uwg->ispecs[2], nla_data(info->attrs[UWGDEVICE_A_I3]));
		if (ret) {
			net_dbg_ratelimited("%s: I3-packet invalid format\n", uwg->dev->name);
			goto out;
		}
	}

	if (info->attrs[UWGDEVICE_A_I4]) {
		ret = jp_spec_setup(&uwg->ispecs[3], nla_data(info->attrs[UWGDEVICE_A_I4]));
		if (ret) {
			net_dbg_ratelimited("%s: I4-packet invalid format\n", uwg->dev->name);
			goto out;
		}
	}

	if (info->attrs[UWGDEVICE_A_I5]) {
		ret = jp_spec_setup(&uwg->ispecs[4], nla_data(info->attrs[UWGDEVICE_A_I5]));
		if (ret) {
			net_dbg_ratelimited("%s: I5-packet invalid format\n", uwg->dev->name);
			goto out;
		}
	}

	if (info->attrs[UWGDEVICE_A_HEADER_PROTECTION_KEY] &&
		nla_len(info->attrs[UWGDEVICE_A_HEADER_PROTECTION_KEY])
			== HEADER_PROTECTION_KEY_SIZE) {
		if (uwg->init_padding < HEADER_PROTECTION_NONCE_SIZE) {
			net_dbg_ratelimited("%s: S1 must be more then %d to use headerProtection\n",
				uwg->dev->name, HEADER_PROTECTION_NONCE_SIZE);
			ret = -EINVAL;
			goto out;
		}
		if (uwg->resp_padding < HEADER_PROTECTION_NONCE_SIZE) {
			net_dbg_ratelimited("%s: S2 must be more then %d to use headerProtection\n",
				uwg->dev->name, HEADER_PROTECTION_NONCE_SIZE);
			ret = -EINVAL;
			goto out;
		}
		if (uwg->cookie_padding < HEADER_PROTECTION_NONCE_SIZE) {
			net_dbg_ratelimited("%s: S3 must be more then %d to use headerProtection\n",
				uwg->dev->name, HEADER_PROTECTION_NONCE_SIZE);
			ret = -EINVAL;
			goto out;
		}
		if (uwg->transport_padding < HEADER_PROTECTION_NONCE_SIZE) {
			net_dbg_ratelimited("%s: S4 must be more then %d to use headerProtection\n",
				uwg->dev->name, HEADER_PROTECTION_NONCE_SIZE);
			ret = -EINVAL;
			goto out;
		}
		uwg_header_protection_set_key(&uwg->header_protection,
			nla_data(info->attrs[UWGDEVICE_A_HEADER_PROTECTION_KEY]));
	}

	if (info->attrs[UWGDEVICE_A_CONTENT_PADDING_ADDITION]) {
		u32 val32 = nla_get_u32(
			info->attrs[UWGDEVICE_A_CONTENT_PADDING_ADDITION]);
		if (val32 && u16_range_lo(val32) > u16_range_hi(val32)) {
			net_dbg_ratelimited(
				"%s: ContentPaddingAddition range invalid\n",
				uwg->dev->name);
			ret = -EINVAL;
			goto out;
		}
		uwg->content_padding_addition = val32;
	}

	if (info->attrs[UWGDEVICE_A_REKEY_AFTER_TIME]) {
		u32 val32 = nla_get_u32(
			info->attrs[UWGDEVICE_A_REKEY_AFTER_TIME]);
		if (val32 && u16_range_lo(val32) > u16_range_hi(val32)) {
			net_dbg_ratelimited("%s: RekeyAfterTime range invalid\n",
					uwg->dev->name);
			ret = -EINVAL;
			goto out;
		}
		uwg->rekey_after_time = val32;
	}

	if (info->attrs[UWGDEVICE_A_REKEY_TIMEOUT]) {
		u32 val32 = nla_get_u32(info->attrs[UWGDEVICE_A_REKEY_TIMEOUT]);
		if (val32 && u16_range_lo(val32) > u16_range_hi(val32)) {
			net_dbg_ratelimited("%s: RekeyTimeout range invalid\n",
					uwg->dev->name);
			ret = -EINVAL;
			goto out;
		}
		uwg->rekey_timeout = val32;
	}

	if (info->attrs[UWGDEVICE_A_REJECT_AFTER_TIME]) {
		u32 val32 = nla_get_u32(
			info->attrs[UWGDEVICE_A_REJECT_AFTER_TIME]);
		if (val32 && u16_range_lo(val32) > u16_range_hi(val32)) {
			net_dbg_ratelimited("%s: RejectAfterTime range invalid\n",
					uwg->dev->name);
			ret = -EINVAL;
			goto out;
		}
		uwg->reject_after_time = val32;
	}

	if (info->attrs[UWGDEVICE_A_KEEPALIVE_TIMEOUT]) {
		u32 val32 = nla_get_u32(
			info->attrs[UWGDEVICE_A_KEEPALIVE_TIMEOUT]);
		if (val32 && u16_range_lo(val32) > u16_range_hi(val32)) {
			net_dbg_ratelimited("%s: KeepaliveTimeout range invalid\n",
					uwg->dev->name);
			ret = -EINVAL;
			goto out;
		}
		uwg->keepalive_timeout = val32;
	}

	if (info->attrs[UWGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS]) {
		u32 val32 = nla_get_u32(
			info->attrs[UWGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS]);
		if (val32 && u16_range_lo(val32) > u16_range_hi(val32)) {
			net_dbg_ratelimited(
				"%s: MaxHandshakeAttempts range invalid\n",
				uwg->dev->name);
			ret = -EINVAL;
			goto out;
		}
		uwg->max_handshake_attempts = val32;
	}

	if (info->attrs[UWGDEVICE_A_RANDOM_TRAILERS]) {
		u8 val8 = nla_get_u8(info->attrs[UWGDEVICE_A_RANDOM_TRAILERS]);
		if (val8 > 1) {
			net_dbg_ratelimited(
				"%s: RandomTrailers must be 0 or 1\n", uwg->dev->name);
			ret = -EINVAL;
			goto out;
		}
		uwg->random_trailers = val8;
	}

	if (info->attrs[UWGDEVICE_A_DISABLE_COOKIES]) {
		u8 val8 = nla_get_u8(info->attrs[UWGDEVICE_A_DISABLE_COOKIES]);
		if (val8 > 1) {
			net_dbg_ratelimited(
				"%s: DisableCookies must be 0 or 1\n", uwg->dev->name);
			ret = -EINVAL;
			goto out;
		}
		uwg->disable_cookies = val8;
	}

	if (flags & UWGDEVICE_F_REPLACE_PEERS)
		uwg_peer_remove_all(uwg);

	if (info->attrs[UWGDEVICE_A_PRIVATE_KEY] &&
	    nla_len(info->attrs[UWGDEVICE_A_PRIVATE_KEY]) ==
		    NOISE_PUBLIC_KEY_LEN) {
		u8 *private_key = nla_data(info->attrs[UWGDEVICE_A_PRIVATE_KEY]);
		u8 public_key[NOISE_PUBLIC_KEY_LEN];
		struct uwg_peer *peer, *temp;

		if (!crypto_memneq(uwg->static_identity.static_private,
				   private_key, NOISE_PUBLIC_KEY_LEN))
			goto skip_set_private_key;

		/* We remove before setting, to prevent race, which means doing
		 * two 25519-genpub ops.
		 */
		if (curve25519_generate_public(public_key, private_key)) {
			peer = uwg_pubkey_hashtable_lookup(uwg->peer_hashtable,
							  public_key);
			if (peer) {
				uwg_peer_put(peer);
				uwg_peer_remove(peer);
			}
		}

		down_write(&uwg->static_identity.lock);
		uwg_noise_set_static_identity_private_key(&uwg->static_identity,
							 private_key);
		list_for_each_entry_safe(peer, temp, &uwg->peer_list,
					 peer_list) {
			uwg_noise_precompute_static_static(peer);
			uwg_noise_expire_current_peer_keypairs(peer);
		}
		uwg_cookie_checker_precompute_device_keys(&uwg->cookie_checker);
		up_write(&uwg->static_identity.lock);
	}
skip_set_private_key:
	if (info->attrs[UWGDEVICE_A_PEERS]) {
		struct nlattr *attr, *peer[UWGPEER_A_MAX + 1];
		int rem;

		nla_for_each_nested(attr, info->attrs[UWGDEVICE_A_PEERS], rem) {
			ret = nla_parse_nested(peer, UWGPEER_A_MAX, attr,
					       peer_policy, NULL);
			if (ret < 0)
				goto out;
			ret = set_peer(uwg, peer);
			if (ret < 0)
				goto out;
		}
	}
	ret = 0;

out:
	mutex_unlock(&uwg->device_update_lock);
	rtnl_unlock();
	dev_put(uwg->dev);
out_nodev:
	if (info->attrs[UWGDEVICE_A_PRIVATE_KEY])
		memzero_explicit(nla_data(info->attrs[UWGDEVICE_A_PRIVATE_KEY]),
				 nla_len(info->attrs[UWGDEVICE_A_PRIVATE_KEY]));
	return ret;
}

static const struct genl_ops genl_ops[] = {
	{
		.cmd = UWG_CMD_GET_DEVICE,
		.start = uwg_get_device_start,
		.dumpit = uwg_get_device_dump,
		.done = uwg_get_device_done,
		.policy = device_policy,
		.flags = GENL_UNS_ADMIN_PERM
	}, {
		.cmd = UWG_CMD_SET_DEVICE,
		.doit = uwg_set_device,
		.policy = device_policy,
		.flags = GENL_UNS_ADMIN_PERM
	}
};

static const struct genl_multicast_group uwg_genl_mcgrps[] = {
	{
		.name = UWG_MULTICAST_GROUP_AUTH
	}
};

static struct genl_family genl_family __ro_after_init = {
	.ops = genl_ops,
	.n_ops = ARRAY_SIZE(genl_ops),
	.resv_start_op = UWG_CMD_SET_DEVICE + 1,
	.name = UWG_GENL_NAME,
	.version = UWG_GENL_VERSION,
	.maxattr = UWGDEVICE_A_MAX,
	.module = THIS_MODULE,
	.netnsok = true,
	.mcgrps = uwg_genl_mcgrps,
	.n_mcgrps = ARRAY_SIZE(uwg_genl_mcgrps)
};

int __init uwg_genetlink_init(void)
{
	return genl_register_family(&genl_family);
}

void __exit uwg_genetlink_uninit(void)
{
	genl_unregister_family(&genl_family);
}

int uwg_genl_mcast_peer_unknown(struct uwg_device *uwg, const u8 pubkey[NOISE_PUBLIC_KEY_LEN],
	                           struct endpoint *endpoint)
{
	struct sk_buff *skb;
	struct nlattr *peer_nest;
	void *hdr;
	int ret = 0;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL)
		return -ENOMEM;

	hdr = genlmsg_put(skb, 0, 0, &genl_family, 0, UWG_CMD_UNKNOWN_PEER);
	if (hdr == NULL) {
		ret = -EMSGSIZE;
		goto err;
	}

	if (nla_put_u32(skb, UWGDEVICE_A_IFINDEX, uwg->dev->ifindex) ||
	    nla_put_string(skb, UWGDEVICE_A_IFNAME, uwg->dev->name)) {
		ret = -EMSGSIZE;
		goto err;
	}

	peer_nest = nla_nest_start(skb, UWGDEVICE_A_PEER);
	if (!peer_nest) {
		ret = -EMSGSIZE;
		goto err;
	}

	ret = nla_put(skb, UWGPEER_A_PUBLIC_KEY, NOISE_PUBLIC_KEY_LEN, pubkey);
	if (ret)
		goto err;

	if (endpoint->addr.sa_family == AF_INET)
		ret = nla_put(skb, UWGPEER_A_ENDPOINT, sizeof(endpoint->addr4), &endpoint->addr4);
	else if (endpoint->addr.sa_family == AF_INET6)
		ret = nla_put(skb, UWGPEER_A_ENDPOINT, sizeof(endpoint->addr6), &endpoint->addr6);

	if (ret)
		goto err;

	ret = nla_put_flag(skb, UWGPEER_A_ADVANCED_SECURITY);
	if (ret)
		goto err;

	nla_nest_end(skb, peer_nest);

	genlmsg_end(skb, hdr);
	ret = genlmsg_multicast_netns(&genl_family, dev_net(uwg->dev), skb, 0, 0, GFP_KERNEL);
	return ret;

err:
	nlmsg_free(skb);
	return ret;
}