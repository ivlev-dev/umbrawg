// SPDX-License-Identifier: GPL-2.0
#include "aead.h"
#include "messages.h"

#include <crypto/aead.h>
#include <crypto/gcm.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>

#define UWG_AEAD_OPS 4

struct uwg_aead_op {
	struct aead_request *req;
	struct scatterlist sg[MAX_SKB_FRAGS + 8];
	struct completion completion;
	struct mutex lock;
	u8 iv[GCM_AES_IV_SIZE];
	int result;
};

struct uwg_aead {
	struct crypto_aead *tfm;
	struct uwg_aead_op ops[UWG_AEAD_OPS];
};

static struct workqueue_struct *uwg_aead_wq;

int uwg_aead_init(void)
{
	uwg_aead_wq = alloc_workqueue("uwg-aead", WQ_MEM_RECLAIM, 0);
	return uwg_aead_wq ? 0 : -ENOMEM;
}

void uwg_aead_uninit(void)
{
	if (uwg_aead_wq)
		destroy_workqueue(uwg_aead_wq);
	uwg_aead_wq = NULL;
}

bool uwg_aead_queue_free(struct work_struct *work)
{
	return uwg_aead_wq && queue_work(uwg_aead_wq, work);
}

static void uwg_aead_done(void *data, int err)
{
	struct uwg_aead_op *op = data;

	op->result = err;
	complete(&op->completion);
}

struct uwg_aead *uwg_aead_alloc(const u8 *key)
{
	struct uwg_aead *aead;
	struct crypto_aead *tfm;
	int ret;
	unsigned int i;

	aead = kzalloc(sizeof(*aead), GFP_KERNEL);
	if (!aead)
		return ERR_PTR(-ENOMEM);

	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		kfree(aead);
		return ERR_CAST(tfm);
	}
	aead->tfm = tfm;

	ret = crypto_aead_setauthsize(tfm, NOISE_AUTHTAG_LEN);
	if (!ret)
		ret = crypto_aead_setkey(tfm, key, NOISE_SYMMETRIC_KEY_LEN);
	if (ret)
		goto err;

	for (i = 0; i < UWG_AEAD_OPS; i++) {
		struct uwg_aead_op *op = &aead->ops[i];

		op->req = aead_request_alloc(tfm, GFP_KERNEL);
		if (!op->req)
			goto err;
		init_completion(&op->completion);
		mutex_init(&op->lock);
		aead_request_set_callback(op->req, 0, uwg_aead_done, op);
	}

	return aead;
err:
	uwg_aead_free(aead);
	return ERR_PTR(ret ?: -ENOMEM);
}

void uwg_aead_free(struct uwg_aead *aead)
{
	unsigned int i;

	if (IS_ERR_OR_NULL(aead))
		return;
	for (i = 0; i < UWG_AEAD_OPS; i++)
		if (aead->ops[i].req)
			aead_request_free(aead->ops[i].req);
	if (aead->tfm)
		crypto_free_aead(aead->tfm);
	kfree_sensitive(aead);
}

static int uwg_aead_crypt(struct uwg_aead *aead, struct sk_buff *skb,
			  unsigned int offset, unsigned int data_len,
			  u64 counter, bool encrypt)
{
	unsigned int total = data_len + NOISE_AUTHTAG_LEN;
	struct uwg_aead_op *op = NULL;
	int ret;
	unsigned int i;

	if (unlikely(skb->len < offset + total))
		return -EINVAL;

	for (i = 0; i < UWG_AEAD_OPS; i++) {
		if (mutex_trylock(&aead->ops[i].lock)) {
			op = &aead->ops[i];
			break;
		}
	}
	if (!op) {
		op = &aead->ops[0];
		mutex_lock(&op->lock);
	}

	sg_init_table(op->sg, ARRAY_SIZE(op->sg));
	if (unlikely(skb_to_sgvec(skb, op->sg, offset, total) <= 0)) {
		ret = -EINVAL;
		goto out;
	}

	put_unaligned_le64(counter, op->iv + 4);
	aead_request_set_crypt(op->req, op->sg, op->sg,
			       encrypt ? data_len : total, op->iv);
	aead_request_set_ad(op->req, 0);
	reinit_completion(&op->completion);
	op->result = -EINPROGRESS;
	ret = encrypt ? crypto_aead_encrypt(op->req) :
			crypto_aead_decrypt(op->req);
	if (ret == -EINPROGRESS || ret == -EBUSY) {
		wait_for_completion(&op->completion);
		ret = op->result;
	}
out:
	mutex_unlock(&op->lock);
	return ret;
}

bool uwg_aead_encrypt(struct uwg_aead *aead, struct sk_buff *skb,
		      unsigned int offset, unsigned int data_len, u64 counter)
{
	return uwg_aead_crypt(aead, skb, offset, data_len, counter, true) == 0;
}

bool uwg_aead_decrypt(struct uwg_aead *aead, struct sk_buff *skb,
		      unsigned int data_len, u64 counter)
{
	return uwg_aead_crypt(aead, skb, 0, data_len, counter, false) == 0;
}
