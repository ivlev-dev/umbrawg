/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _UWG_AEAD_H
#define _UWG_AEAD_H

#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/workqueue.h>

struct uwg_aead;

int uwg_aead_init(void);
void uwg_aead_uninit(void);
bool uwg_aead_queue_free(struct work_struct *work);

struct uwg_aead *uwg_aead_alloc(const u8 *key);
void uwg_aead_free(struct uwg_aead *aead);
bool uwg_aead_encrypt(struct uwg_aead *aead, struct sk_buff *skb,
		      unsigned int offset, unsigned int data_len, u64 counter);
bool uwg_aead_decrypt(struct uwg_aead *aead, struct sk_buff *skb,
		      unsigned int data_len, u64 counter);

#endif /* _UWG_AEAD_H */
