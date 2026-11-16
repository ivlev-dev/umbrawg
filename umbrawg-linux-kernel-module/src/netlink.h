/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _UWG_NETLINK_H
#define _UWG_NETLINK_H

#include "peer.h"
#include "noise.h"

extern int bogus_endpoints;
extern char *bogus_endpoints_prefix;
extern char *bogus_endpoints_prefix6;

int uwg_genl_mcast_peer_unknown(struct uwg_device *uwg, const u8 pubkey[NOISE_PUBLIC_KEY_LEN],
	                           struct endpoint *endpoint);
int uwg_genetlink_init(void);
void uwg_genetlink_uninit(void);

#endif /* _UWG_NETLINK_H */
