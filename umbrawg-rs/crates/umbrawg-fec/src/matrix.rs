use crate::{FecError, MAX_TOTAL_SHARDS};

use crate::gf;

pub(crate) struct RSCode {
    k: usize,
    m: usize,
    parity: Vec<u8>,
}

impl RSCode {
    pub(crate) fn try_new(k: usize, m: usize) -> Result<Self, FecError> {
        if k == 0 {
            return Err(FecError::ZeroDataShards);
        }
        if m == 0 {
            return Err(FecError::ZeroParityShards);
        }
        if k + m > MAX_TOTAL_SHARDS {
            return Err(FecError::TooManyShards {
                data_shards: k as u8,
                parity_shards: m as u8,
            });
        }
        let total = k + m;
        let mut vandermonde = vec![0u8; total * k];
        for row in 0..total {
            let node = row as u8;
            let mut value = 1u8;
            for column in 0..k {
                vandermonde[row * k + column] = value;
                value = gf::mul(value, node);
            }
        }
        let Some(inverse) = invert(&vandermonde[..k * k], k) else {
            return Err(FecError::TooManyShards {
                data_shards: k as u8,
                parity_shards: m as u8,
            });
        };
        let mut parity = vec![0u8; m * k];
        for row in 0..m {
            for column in 0..k {
                let mut accumulator = 0u8;
                for inner in 0..k {
                    let left = vandermonde[(k + row) * k + inner];
                    let right = inverse[inner * k + column];
                    accumulator ^= gf::mul(left, right);
                }
                parity[row * k + column] = accumulator;
            }
        }
        Ok(Self { k, m, parity })
    }

    pub(crate) fn k(&self) -> usize {
        self.k
    }

    pub(crate) fn m(&self) -> usize {
        self.m
    }

    pub(crate) fn coefficient(&self, row: usize, column: usize) -> u8 {
        self.parity[row * self.k + column]
    }
}

pub(crate) fn invert(matrix: &[u8], n: usize) -> Option<Vec<u8>> {
    if n == 0 {
        return Some(Vec::new());
    }
    if matrix.len() != n * n {
        return None;
    }
    let stride = 2 * n;
    let mut work = vec![0u8; n * stride];
    for row in 0..n {
        work[row * stride..row * stride + n].copy_from_slice(&matrix[row * n..(row + 1) * n]);
        work[row * stride + n + row] = 1;
    }
    for column in 0..n {
        let pivot = (column..n).find(|&row| work[row * stride + column] != 0)?;
        if pivot != column {
            for offset in 0..stride {
                work.swap(column * stride + offset, pivot * stride + offset);
            }
        }
        let scale = gf::inv(work[column * stride + column]);
        for offset in 0..stride {
            work[column * stride + offset] = gf::mul(work[column * stride + offset], scale);
        }
        for row in 0..n {
            if row == column {
                continue;
            }
            let factor = work[row * stride + column];
            if factor == 0 {
                continue;
            }
            for offset in 0..stride {
                let value = gf::mul(work[column * stride + offset], factor);
                work[row * stride + offset] ^= value;
            }
        }
    }
    let mut inverse = vec![0u8; n * n];
    for row in 0..n {
        inverse[row * n..(row + 1) * n]
            .copy_from_slice(&work[row * stride + n..row * stride + 2 * n]);
    }
    Some(inverse)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generator_row(code: &RSCode, row: usize) -> Vec<u8> {
        if row < code.k() {
            let mut unit = vec![0u8; code.k()];
            unit[row] = 1;
            unit
        } else {
            (0..code.k())
                .map(|column| code.coefficient(row - code.k(), column))
                .collect()
        }
    }

    fn subset_rows(k: usize, m: usize, mask: u32) -> Vec<u8> {
        let code = RSCode::try_new(k, m).expect("valid code");
        assert_eq!(code.k(), k);
        assert_eq!(code.m(), m);
        let mut matrix = Vec::with_capacity(k * k);
        for row in 0..(k + m) {
            if mask & (1 << row) != 0 {
                matrix.extend_from_slice(&generator_row(&code, row));
            }
        }
        assert_eq!(matrix.len(), k * k);
        matrix
    }

    fn assert_mds(k: usize, m: usize) {
        let code = RSCode::try_new(k, m).expect("valid code");
        for row in 0..m {
            for column in 0..k {
                assert_ne!(
                    code.coefficient(row, column),
                    0,
                    "parity coefficient ({row}, {column}) must be non-zero"
                );
            }
        }
        for mask in 0u32..(1 << (k + m)) {
            if mask.count_ones() as usize != k {
                continue;
            }
            let matrix = subset_rows(k, m, mask);
            assert!(
                invert(&matrix, k).is_some(),
                "rows {mask:b} must be invertible for k={k} m={m}"
            );
        }
    }

    #[test]
    fn vandermonde_generator_is_mds() {
        assert_mds(1, 1);
        assert_mds(2, 1);
        assert_mds(4, 2);
        assert_mds(5, 2);
    }

    #[test]
    fn vandermonde_generator_is_mds_for_wide_blocks() {
        let code = RSCode::try_new(10, 3).expect("valid code");
        for row in 0..code.m() {
            for column in 0..code.k() {
                assert_ne!(code.coefficient(row, column), 0);
            }
        }
        let total = 1u32 << 13;
        for mask in 0u32..total {
            if mask.count_ones() != 10 {
                continue;
            }
            let matrix = subset_rows(10, 3, mask);
            assert!(invert(&matrix, 10).is_some(), "rows {mask:b}");
        }
    }

    #[test]
    fn invert_identity_and_singular() {
        let identity = [1u8, 0, 0, 1];
        assert_eq!(invert(&identity, 2), Some(vec![1, 0, 0, 1]));
        let singular = [1u8, 2, 2, 4];
        assert_eq!(invert(&singular, 2), None);
        assert_eq!(invert(&[], 0), Some(Vec::new()));
        assert_eq!(invert(&[1, 2, 3], 2), None);
    }

    #[test]
    fn invert_produces_left_inverse() {
        let matrix = [3u8, 1, 5, 7];
        let inverse = invert(&matrix, 2).expect("matrix is invertible");
        for row in 0..2 {
            for column in 0..2 {
                let mut accumulator = 0u8;
                for inner in 0..2 {
                    accumulator ^= gf::mul(matrix[row * 2 + inner], inverse[inner * 2 + column]);
                }
                assert_eq!(accumulator, u8::from(row == column));
            }
        }
    }
}
