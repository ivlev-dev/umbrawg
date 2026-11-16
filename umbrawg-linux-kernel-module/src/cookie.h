/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _UWG_COOKIE_H
#define _UWG_COOKIE_H

#include "messages.h"
#include <linux/rwsem.h>

struct uwg_peer;

struct cookie_checker {
	u8 secret[NOISE_HASH_LEN];
	u8 cookie_encryption_key[NOISE_SYMMETRIC_KEY_LEN];
	u8 message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
	u64 secret_birthdate;
	struct rw_semaphore secret_lock;
	struct uwg_device *device;
};

struct cookie {
	u64 birthdate;
	bool is_valid;
	u8 cookie[COOKIE_LEN];
	bool have_sent_mac1;
	u8 last_mac1_sent[COOKIE_LEN];
	u8 cookie_decryption_key[NOISE_SYMMETRIC_KEY_LEN];
	u8 message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
	struct rw_semaphore lock;
};

enum cookie_mac_state {
	INVALID_MAC,
	VALID_MAC_BUT_NO_COOKIE,
	VALID_MAC_WITH_COOKIE_BUT_RATELIMITED,
	VALID_MAC_WITH_COOKIE
};

void uwg_cookie_checker_init(struct cookie_checker *checker,
			    struct uwg_device *uwg);
void uwg_cookie_checker_precompute_device_keys(struct cookie_checker *checker);
void uwg_cookie_checker_precompute_peer_keys(struct uwg_peer *peer);
void uwg_cookie_init(struct cookie *cookie);

enum cookie_mac_state uwg_cookie_validate_packet(struct cookie_checker *checker,
						struct sk_buff *skb,
						bool check_cookie);
void uwg_cookie_add_mac_to_packet(void *message, size_t len,
				 struct uwg_peer *peer);

void uwg_cookie_message_create(struct message_handshake_cookie *src,
			      struct sk_buff *skb, __le32 index,
			      struct cookie_checker *checker, u32 message_type);
void uwg_cookie_message_consume(struct message_handshake_cookie *src,
			       struct uwg_device *uwg);

#endif /* _UWG_COOKIE_H */
