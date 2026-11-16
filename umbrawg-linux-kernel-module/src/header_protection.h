#ifndef _UWG_HEADER_PROTECTION
#define _UWG_HEADER_PROTECTION

#include "messages.h"

#include <linux/types.h>
#include <crypto/chacha.h>

struct uwg_device;

enum header_protection_lengths {
    HEADER_PROTECTION_KEY_SIZE = CHACHA_KEY_SIZE,
    HEADER_PROTECTION_NONCE_SIZE = 12,
};

struct header_protection {
    u32 key[CHACHA_KEY_WORDS];
    struct rw_semaphore lock;
    bool has_protection;
};

bool uwg_header_protection_init(struct chacha_state *state, struct uwg_device *dev, u8 *nonce);
void uwg_header_protection_set_key(struct header_protection *p, u8 key[HEADER_PROTECTION_KEY_SIZE]);
void uwg_header_protection_get_key(struct header_protection *p, u8 key[HEADER_PROTECTION_KEY_SIZE]);

#endif
