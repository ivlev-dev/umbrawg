/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _UWG_FEC_H
#define _UWG_FEC_H

#include <linux/types.h>

#define UWG_FEC_MAX_DATA 32
#define UWG_FEC_MAX_PARITY 16
#define UWG_FEC_MAX_TOTAL (UWG_FEC_MAX_DATA + UWG_FEC_MAX_PARITY)
#define UWG_FEC_MAX_SHARD_LEN 0xffff

int uwg_fec_init(void);
int uwg_fec_encode(u8 k, u8 m, size_t shard_len, const u8 *data, u8 *parity);
int uwg_fec_decode(u8 k, u8 m, size_t shard_len, u8 **shards,
		   const bool *present);
int uwg_fec_selftest(void);

#endif /* _UWG_FEC_H */
