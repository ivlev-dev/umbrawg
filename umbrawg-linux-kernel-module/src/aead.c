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

static struct workqueue_struct *uwg_aead_wq;

struct uwg_aead {
	struct crypto_aead *tfm;
	struct aead_request *req;
	struct scatterlist sg[MAX_SKB_FRAGS + 8];
	struct completion completion;
	struct mutex lock;
	u8 iv[GCM_AES_IV_SIZE];
	int result;
};

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
	struct uwg_aead *aead = data;

	aead->result = err;
	complete(&aead->completion);
}

struct uwg_aead *uwg_aead_alloc(const u8 *key)
{
	struct uwg_aead *aead;
	struct crypto_aead *tfm;
	int ret;

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

	aead->req = aead_request_alloc(tfm, GFP_KERNEL);
	if (ret || !aead->req) {
		if (!ret)
			ret = -ENOMEM;
		uwg_aead_free(aead);
		return ERR_PTR(ret);
	}

	init_completion(&aead->completion);
	mutex_init(&aead->lock);
	aead_request_set_callback(aead->req, 0, uwg_aead_done, aead);
	return aead;
}

void uwg_aead_free(struct uwg_aead *aead)
{
	if (IS_ERR_OR_NULL(aead))
		return;
	if (aead->req)
		aead_request_free(aead->req);
	if (aead->tfm)
		crypto_free_aead(aead->tfm);
	kfree_sensitive(aead);
}

static int uwg_aead_crypt(struct uwg_aead *aead, struct sk_buff *skb,
			  unsigned int offset, unsigned int data_len,
			  u64 counter, bool encrypt)
{
	unsigned int total = data_len + NOISE_AUTHTAG_LEN;
	int ret;

	if (unlikely(skb->len < offset + total))
		return -EINVAL;

	mutex_lock(&aead->lock);
	sg_init_table(aead->sg, ARRAY_SIZE(aead->sg));
	if (unlikely(skb_to_sgvec(skb, aead->sg, offset, total) <= 0)) {
		ret = -EINVAL;
		goto out;
	}

	put_unaligned_le64(counter, aead->iv + 4);
	aead_request_set_crypt(aead->req, aead->sg, aead->sg,
			       encrypt ? data_len : total, aead->iv);
	aead_request_set_ad(aead->req, 0);
	reinit_completion(&aead->completion);
	aead->result = -EINPROGRESS;
	ret = encrypt ? crypto_aead_encrypt(aead->req) :
			crypto_aead_decrypt(aead->req);
	if (ret == -EINPROGRESS || ret == -EBUSY) {
		wait_for_completion(&aead->completion);
		ret = aead->result;
	}
out:
	mutex_unlock(&aead->lock);
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
