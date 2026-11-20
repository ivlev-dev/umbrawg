#include "header_protection.h"
#include "device.h"

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <crypto/chacha.h>

bool uwg_header_protection_init(struct chacha_state *state,
				struct uwg_device *uwg, const u8 *nonce)
{
	const struct uwg_header_protection *hp;
	bool res = false;
	u8 iv[16];

	rcu_read_lock();
	hp = rcu_dereference(uwg->header_protection);
	if (hp && hp->enabled) {
		memset(iv, 0, 4);
		memcpy(iv + 4, nonce, 12);
		chacha_init(state, hp->key, iv);
		res = true;
	}
	rcu_read_unlock();

	return res;
}

bool uwg_header_protection_enabled(struct uwg_device *uwg)
{
	const struct uwg_header_protection *hp;
	bool enabled;

	rcu_read_lock();
	hp = rcu_dereference(uwg->header_protection);
	enabled = hp && hp->enabled;
	rcu_read_unlock();

	return enabled;
}

/* Called with device_update_lock held. The new block is published first and
 * the old one is only freed once every reader has left its RCU section, so the
 * hot path never has to take a sleeping lock.
 */
int uwg_header_protection_set_key(struct uwg_device *uwg, const u8 *key)
{
	struct uwg_header_protection *new_key;
	void *old_key;

	lockdep_assert_held(&uwg->device_update_lock);

	new_key = kzalloc(sizeof(*new_key), GFP_KERNEL);
	if (unlikely(!new_key))
		return -ENOMEM;

	new_key->key[0] = get_unaligned_le32(key + 0);
	new_key->key[1] = get_unaligned_le32(key + 4);
	new_key->key[2] = get_unaligned_le32(key + 8);
	new_key->key[3] = get_unaligned_le32(key + 12);
	new_key->key[4] = get_unaligned_le32(key + 16);
	new_key->key[5] = get_unaligned_le32(key + 20);
	new_key->key[6] = get_unaligned_le32(key + 24);
	new_key->key[7] = get_unaligned_le32(key + 28);
	new_key->enabled = true;

	old_key = rcu_replace_pointer(uwg->header_protection, new_key,
				      lockdep_is_held(&uwg->device_update_lock));
	synchronize_net();
	kfree_sensitive(old_key);

	return 0;
}

bool uwg_header_protection_get_key(struct uwg_device *uwg, u8 *key)
{
	const struct uwg_header_protection *hp;
	bool enabled;

	rcu_read_lock();
	hp = rcu_dereference(uwg->header_protection);
	enabled = hp && hp->enabled;
	if (enabled) {
		put_unaligned_le32(hp->key[0], key + 0);
		put_unaligned_le32(hp->key[1], key + 4);
		put_unaligned_le32(hp->key[2], key + 8);
		put_unaligned_le32(hp->key[3], key + 12);
		put_unaligned_le32(hp->key[4], key + 16);
		put_unaligned_le32(hp->key[5], key + 20);
		put_unaligned_le32(hp->key[6], key + 24);
		put_unaligned_le32(hp->key[7], key + 28);
	}
	rcu_read_unlock();

	return enabled;
}

/* Called with device_update_lock held while the device is being torn down. */
void uwg_header_protection_release(struct uwg_device *uwg)
{
	void *hp;

	lockdep_assert_held(&uwg->device_update_lock);

	hp = rcu_replace_pointer(uwg->header_protection, NULL,
				 lockdep_is_held(&uwg->device_update_lock));
	if (!hp)
		return;

	synchronize_net();
	kfree_sensitive(hp);
}
