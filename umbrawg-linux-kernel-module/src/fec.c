/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "fec.h"
#include "fec_data.h"

#define UWG_FEC_POLY 0x11d
#define UWG_FEC_ORDER 255
#define UWG_FEC_EXP_LEN 512
#define UWG_FEC_MAX_WORK (UWG_FEC_MAX_DATA * UWG_FEC_MAX_TOTAL)
#define UWG_FEC_MAX_AUG (UWG_FEC_MAX_PARITY * 2 * UWG_FEC_MAX_PARITY)

/* Profiles the data path actually uses (fec_data.h: k <= 8, m <= 2). Every
 * other valid combination is still computed on demand for the self-test.
 */
#define UWG_FEC_CACHE_K 8
#define UWG_FEC_CACHE_M 2

static u8 uwg_gf_exp[UWG_FEC_EXP_LEN];
static u8 uwg_gf_log[256];
static u8 uwg_fec_parity_cache[UWG_FEC_CACHE_K][UWG_FEC_CACHE_M]
			       [UWG_FEC_CACHE_K * UWG_FEC_CACHE_M];
static bool uwg_fec_ready;

static int uwg_fec_parity_matrix(u8 k, u8 m, u8 *p);

int uwg_fec_init(void)
{
	u16 value = 1;
	unsigned int i, k, m;

	if (READ_ONCE(uwg_fec_ready))
		return 0;

	for (i = 0; i < UWG_FEC_ORDER; i++) {
		uwg_gf_exp[i] = (u8)value;
		uwg_gf_log[value] = (u8)i;
		value <<= 1;
		if (value & 0x100)
			value ^= UWG_FEC_POLY;
	}

	for (i = UWG_FEC_ORDER; i < UWG_FEC_EXP_LEN; i++)
		uwg_gf_exp[i] = uwg_gf_exp[i - UWG_FEC_ORDER];

	/* Solving for the parity matrix is O(k^3) and the result only depends
	 * on (k, m): build every hot profile once instead of per block.
	 */
	for (k = 1; k <= UWG_FEC_CACHE_K; k++)
		for (m = 1; m <= UWG_FEC_CACHE_M; m++)
			if (uwg_fec_parity_matrix((u8)k, (u8)m,
						  uwg_fec_parity_cache[k - 1][m - 1]))
				return -EINVAL;

	smp_wmb();
	WRITE_ONCE(uwg_fec_ready, true);

	return 0;
}

static inline u8 uwg_gf_mul(u8 a, u8 b)
{
	if (!a || !b)
		return 0;
	return uwg_gf_exp[(unsigned int)uwg_gf_log[a] + uwg_gf_log[b]];
}

static inline u8 uwg_gf_inv(u8 a)
{
	if (!a)
		return 0;
	return uwg_gf_exp[UWG_FEC_ORDER - uwg_gf_log[a]];
}

static inline u8 uwg_gf_pow(u8 node, unsigned int exponent)
{
	u8 value = 1;
	unsigned int i;

	for (i = 0; i < exponent; i++)
		value = uwg_gf_mul(value, node);

	return value;
}

static void uwg_gf_mul_add(u8 *dst, const u8 *src, u8 coeff, size_t len)
{
	unsigned int log_coeff;
	size_t i;

	if (!coeff)
		return;

	if (coeff == 1) {
		for (i = 0; i < len; i++)
			dst[i] ^= src[i];
		return;
	}

	log_coeff = uwg_gf_log[coeff];
	for (i = 0; i < len; i++) {
		if (src[i])
			dst[i] ^= uwg_gf_exp[log_coeff + uwg_gf_log[src[i]]];
	}
}

static void uwg_gf_swap_rows(u8 *mat, unsigned int stride, unsigned int a,
			     unsigned int b)
{
	unsigned int j;

	for (j = 0; j < stride; j++) {
		u8 tmp = mat[a * stride + j];

		mat[a * stride + j] = mat[b * stride + j];
		mat[b * stride + j] = tmp;
	}
}

static int uwg_gf_invert(const u8 *src, unsigned int n, u8 *dst)
{
	u8 work[UWG_FEC_MAX_AUG];
	unsigned int stride, row, col, j;
	u8 scale, factor;

	if (!n)
		return 0;
	if (n > UWG_FEC_MAX_PARITY)
		return -EINVAL;

	stride = 2 * n;
	memset(work, 0, (size_t)n * stride);

	for (row = 0; row < n; row++) {
		for (col = 0; col < n; col++)
			work[row * stride + col] = src[row * n + col];
		work[row * stride + n + row] = 1;
	}

	for (col = 0; col < n; col++) {
		unsigned int pivot = col;

		while (pivot < n && !work[pivot * stride + col])
			pivot++;
		if (pivot == n)
			return -EINVAL;
		if (pivot != col)
			uwg_gf_swap_rows(work, stride, col, pivot);

		scale = uwg_gf_inv(work[col * stride + col]);
		for (j = 0; j < stride; j++)
			work[col * stride + j] =
				uwg_gf_mul(work[col * stride + j], scale);

		for (row = 0; row < n; row++) {
			if (row == col)
				continue;
			factor = work[row * stride + col];
			if (!factor)
				continue;
			for (j = 0; j < stride; j++)
				work[row * stride + j] ^=
					uwg_gf_mul(factor, work[col * stride + j]);
		}
	}

	for (row = 0; row < n; row++)
		for (col = 0; col < n; col++)
			dst[row * n + col] = work[row * stride + n + col];

	return 0;
}

static int uwg_fec_parity_matrix(u8 k, u8 m, u8 *p)
{
	u8 work[UWG_FEC_MAX_WORK];
	unsigned int stride = (unsigned int)k + m;
	unsigned int row, col, j;
	u8 factor, scale;

	for (row = 0; row < k; row++)
		for (col = 0; col < k; col++)
			work[row * stride + col] = uwg_gf_pow((u8)col, row);

	for (row = 0; row < k; row++)
		for (col = 0; col < m; col++)
			work[row * stride + k + col] =
				uwg_gf_pow((u8)(k + col), row);

	for (col = 0; col < k; col++) {
		unsigned int pivot = col;

		while (pivot < k && !work[pivot * stride + col])
			pivot++;
		if (pivot == k)
			return -EINVAL;
		if (pivot != col)
			uwg_gf_swap_rows(work, stride, col, pivot);

		scale = uwg_gf_inv(work[col * stride + col]);
		for (j = 0; j < stride; j++)
			work[col * stride + j] =
				uwg_gf_mul(work[col * stride + j], scale);

		for (row = 0; row < k; row++) {
			if (row == col)
				continue;
			factor = work[row * stride + col];
			if (!factor)
				continue;
			for (j = 0; j < stride; j++)
				work[row * stride + j] ^=
					uwg_gf_mul(factor, work[col * stride + j]);
		}
	}

	for (row = 0; row < m; row++)
		for (col = 0; col < k; col++)
			p[row * k + col] = work[col * stride + k + row];

	return 0;
}

static int uwg_fec_parity_get(u8 k, u8 m, u8 *p)
{
	if (k <= UWG_FEC_CACHE_K && m <= UWG_FEC_CACHE_M) {
		memcpy(p, uwg_fec_parity_cache[k - 1][m - 1], (size_t)k * m);
		return 0;
	}

	return uwg_fec_parity_matrix(k, m, p);
}

static bool uwg_fec_valid(u8 k, u8 m)
{
	return k >= 1 && k <= UWG_FEC_MAX_DATA &&
	       m >= 1 && m <= UWG_FEC_MAX_PARITY;
}

int uwg_fec_encode(u8 k, u8 m, size_t shard_len, const u8 *data, u8 *parity)
{
	u8 p[UWG_FEC_MAX_PARITY * UWG_FEC_MAX_DATA];
	unsigned int row, col;
	int ret;

	if (!uwg_fec_valid(k, m) || !data || !parity ||
	    shard_len > UWG_FEC_MAX_SHARD_LEN)
		return -EINVAL;

	if (!READ_ONCE(uwg_fec_ready))
		return -EINVAL;

	ret = uwg_fec_parity_get(k, m, p);
	if (ret < 0)
		return ret;

	for (row = 0; row < m; row++) {
		u8 *out = parity + (size_t)row * shard_len;

		memset(out, 0, shard_len);
		for (col = 0; col < k; col++)
			uwg_gf_mul_add(out, data + (size_t)col * shard_len,
				       p[row * k + col], shard_len);
	}

	return 0;
}

int uwg_fec_decode(u8 k, u8 m, size_t shard_len, u8 **shards,
		   const bool *present)
{
	u8 p[UWG_FEC_MAX_PARITY * UWG_FEC_MAX_DATA];
	u8 matrix[UWG_FEC_MAX_PARITY * UWG_FEC_MAX_PARITY];
	u8 missing[UWG_FEC_MAX_PARITY];
	u8 rows[UWG_FEC_MAX_PARITY];
	unsigned int n_missing = 0, n_rows = 0;
	unsigned int total, i, j, r, c;
	int ret;

	if (!uwg_fec_valid(k, m) || !shards || !present ||
	    shard_len > UWG_FEC_MAX_SHARD_LEN)
		return -EINVAL;

	if (!READ_ONCE(uwg_fec_ready))
		return -EINVAL;

	total = (unsigned int)k + m;
	for (i = 0; i < total; i++) {
		if ((i < k || present[i]) && !shards[i])
			return -EINVAL;
		if (i >= k || present[i])
			continue;
		if (n_missing == m)
			return -ENODATA;
		missing[n_missing++] = (u8)i;
	}

	if (!n_missing)
		return 0;

	ret = uwg_fec_parity_get(k, m, p);
	if (ret < 0)
		return ret;

	for (i = k; i < total; i++) {
		if (!present[i])
			continue;
		rows[n_rows++] = (u8)(i - k);
		if (n_rows == n_missing)
			break;
	}

	if (n_rows < n_missing)
		return -ENODATA;

	for (r = 0; r < n_missing; r++)
		for (c = 0; c < n_missing; c++)
			matrix[r * n_missing + c] = p[rows[r] * k + missing[c]];

	ret = uwg_gf_invert(matrix, n_missing, matrix);
	if (ret < 0)
		return ret;

	for (c = 0; c < n_missing; c++) {
		u8 *out = shards[missing[c]];

		memset(out, 0, shard_len);
		for (r = 0; r < n_missing; r++)
			uwg_gf_mul_add(out, shards[k + rows[r]],
				       matrix[c * n_missing + r], shard_len);
		for (j = 0; j < k; j++) {
			u8 acc = 0;

			if (!present[j])
				continue;
			for (r = 0; r < n_missing; r++)
				acc ^= uwg_gf_mul(matrix[c * n_missing + r],
						  p[rows[r] * k + j]);
			uwg_gf_mul_add(out, shards[j], acc, shard_len);
		}
	}

	return 0;
}

static int uwg_fec_selftest_config(u8 k, u8 m)
{
	const size_t shard_len = 64;
	const size_t data_len = (size_t)k * shard_len;
	const size_t total_len = (size_t)(k + m) * shard_len;
	u8 *buf, *work, *truth;
	u8 *shards[UWG_FEC_MAX_TOTAL];
	bool present[UWG_FEC_MAX_TOTAL];
	unsigned int total = (unsigned int)k + m;
	unsigned int mask, limit, i;
	int ret = 0;

	buf = kmalloc(total_len, GFP_KERNEL);
	work = kmalloc(total_len, GFP_KERNEL);
	truth = kmalloc(data_len, GFP_KERNEL);
	if (!buf || !work || !truth) {
		ret = -ENOMEM;
		goto out;
	}

	get_random_bytes(buf, data_len);
	memcpy(truth, buf, data_len);

	ret = uwg_fec_encode(k, m, shard_len, buf, buf + data_len);
	if (ret < 0) {
		pr_err("FEC self-test: encode k=%u m=%u failed: %d\n",
		       k, m, ret);
		goto out;
	}

	limit = 1u << total;
	for (mask = 0; mask < limit; mask++) {
		if (hweight32(mask) > m)
			continue;

		memcpy(work, buf, total_len);
		for (i = 0; i < total; i++) {
			shards[i] = work + (size_t)i * shard_len;
			present[i] = !(mask & (1u << i));
		}
		for (i = 0; i < k; i++) {
			if (!present[i])
				memset(shards[i], 0, shard_len);
		}

		ret = uwg_fec_decode(k, m, shard_len, shards, present);
		if (ret < 0) {
			pr_err("FEC self-test: decode k=%u m=%u mask=%#x failed: %d\n",
			       k, m, mask, ret);
			goto out;
		}

		for (i = 0; i < k; i++) {
			if (memcmp(shards[i], truth + (size_t)i * shard_len,
				   shard_len)) {
				pr_err("FEC self-test: data mismatch k=%u m=%u mask=%#x shard=%u\n",
				       k, m, mask, i);
				ret = -EINVAL;
				goto out;
			}
		}
	}

	if (k > m) {
		unsigned int bad_mask = (1u << (m + 1)) - 1;

		memcpy(work, buf, total_len);
		for (i = 0; i < total; i++) {
			shards[i] = work + (size_t)i * shard_len;
			present[i] = !(bad_mask & (1u << i));
		}
		for (i = 0; i < k; i++) {
			if (!present[i])
				memset(shards[i], 0, shard_len);
		}
		if (uwg_fec_decode(k, m, shard_len, shards, present) >= 0) {
			pr_err("FEC self-test: decode accepted %u erasures k=%u m=%u\n",
			       m + 1, k, m);
			ret = -EINVAL;
			goto out;
		}
	}

out:
	kfree(buf);
	kfree(work);
	kfree(truth);
	return ret;
}

int uwg_fec_selftest(void)
{
	int ret;

	ret = uwg_fec_init();
	if (ret < 0)
		return ret;

	ret = uwg_fec_selftest_config(4, 2);
	if (ret < 0)
		return ret;

	ret = uwg_fec_selftest_config(10, 3);
	if (ret < 0)
		return ret;

	if (uwg_fec_encode(0, 1, 8, NULL, NULL) != -EINVAL ||
	    uwg_fec_encode(1, 0, 8, NULL, NULL) != -EINVAL ||
	    uwg_fec_encode(UWG_FEC_MAX_DATA + 1, 1, 8, NULL, NULL) != -EINVAL ||
	    uwg_fec_encode(1, UWG_FEC_MAX_PARITY + 1, 8, NULL, NULL) != -EINVAL)
		return -EINVAL;

	return uwg_fec_mtu_selftest();
}
