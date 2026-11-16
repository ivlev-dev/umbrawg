/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _UWG_PEERLOOKUP_H
#define _UWG_PEERLOOKUP_H

#include "messages.h"

#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/siphash.h>

struct uwg_peer;

struct pubkey_hashtable {
	/* TODO: move to rhashtable */
	DECLARE_HASHTABLE(hashtable, 11);
	siphash_key_t key;
	struct mutex lock;
};

struct pubkey_hashtable *uwg_pubkey_hashtable_alloc(void);
void uwg_pubkey_hashtable_add(struct pubkey_hashtable *table,
			     struct uwg_peer *peer);
void uwg_pubkey_hashtable_remove(struct pubkey_hashtable *table,
				struct uwg_peer *peer);
struct uwg_peer *
uwg_pubkey_hashtable_lookup(struct pubkey_hashtable *table,
			   const u8 pubkey[NOISE_PUBLIC_KEY_LEN]);

struct index_hashtable {
	/* TODO: move to rhashtable */
	DECLARE_HASHTABLE(hashtable, 13);
	spinlock_t lock;
};

enum index_hashtable_type {
	INDEX_HASHTABLE_HANDSHAKE = 1U << 0,
	INDEX_HASHTABLE_KEYPAIR = 1U << 1
};

struct index_hashtable_entry {
	struct uwg_peer *peer;
	struct hlist_node index_hash;
	enum index_hashtable_type type;
	__le32 index;
};

struct index_hashtable *uwg_index_hashtable_alloc(void);
__le32 uwg_index_hashtable_insert(struct index_hashtable *table,
				 struct index_hashtable_entry *entry);
bool uwg_index_hashtable_replace(struct index_hashtable *table,
				struct index_hashtable_entry *old,
				struct index_hashtable_entry *new);
void uwg_index_hashtable_remove(struct index_hashtable *table,
			       struct index_hashtable_entry *entry);
struct index_hashtable_entry *
uwg_index_hashtable_lookup(struct index_hashtable *table,
			  const enum index_hashtable_type type_mask,
			  const __le32 index, struct uwg_peer **peer);

#endif /* _UWG_PEERLOOKUP_H */
