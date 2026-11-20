#ifndef _UWG_HEADER_PROTECTION
#define _UWG_HEADER_PROTECTION

#include "messages.h"

#include <linux/rcupdate.h>
#include <linux/types.h>
#include <crypto/chacha.h>

struct uwg_device;

enum header_protection_lengths {
	HEADER_PROTECTION_KEY_SIZE = CHACHA_KEY_SIZE,
	HEADER_PROTECTION_NONCE_SIZE = 12,
};

/* Immutable once published: readers only take it under rcu_read_lock(), the
 * netlink path swaps the whole block and frees the old one after a grace
 * period. A NULL pointer means header protection is off.
 */
struct uwg_header_protection {
	u32 key[CHACHA_KEY_WORDS];
	bool enabled;
};

bool uwg_header_protection_init(struct chacha_state *state, struct uwg_device *dev,
				const u8 *nonce);
bool uwg_header_protection_enabled(struct uwg_device *dev);
int uwg_header_protection_set_key(struct uwg_device *dev, const u8 *key);
bool uwg_header_protection_get_key(struct uwg_device *dev, u8 *key);
void uwg_header_protection_release(struct uwg_device *dev);

#endif
