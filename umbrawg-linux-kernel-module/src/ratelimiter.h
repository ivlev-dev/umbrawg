/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _UWG_RATELIMITER_H
#define _UWG_RATELIMITER_H

#include <linux/skbuff.h>

int uwg_ratelimiter_init(void);
void uwg_ratelimiter_uninit(void);
bool uwg_ratelimiter_allow(struct sk_buff *skb, struct net *net);

#ifdef DEBUG
bool uwg_ratelimiter_selftest(void);
#endif

#endif /* _UWG_RATELIMITER_H */
