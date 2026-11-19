use crate::{FecError, MAX_TOTAL_SHARDS};

/// Shape of a systematic Reed-Solomon block.
///
/// A block contains exactly `data_shards` packets and `parity_shards` parity
/// shards. Any `data_shards` of the `data_shards + parity_shards` shards are
/// enough to recover all packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FecConfig {
    /// Number of data shards `k`, at least 1.
    pub data_shards: u8,
    /// Number of parity shards `m`, at least 1.
    pub parity_shards: u8,
}

impl FecConfig {
    /// Creates and validates a configuration.
    ///
    /// # Errors
    ///
    /// Returns [`FecError::ZeroDataShards`] for `k == 0`,
    /// [`FecError::ZeroParityShards`] for `m == 0` and
    /// [`FecError::TooManyShards`] when `k + m > 255`.
    pub const fn new(data_shards: u8, parity_shards: u8) -> Result<Self, FecError> {
        if data_shards == 0 {
            return Err(FecError::ZeroDataShards);
        }
        if parity_shards == 0 {
            return Err(FecError::ZeroParityShards);
        }
        if data_shards as usize + parity_shards as usize > MAX_TOTAL_SHARDS {
            return Err(FecError::TooManyShards {
                data_shards,
                parity_shards,
            });
        }
        Ok(Self {
            data_shards,
            parity_shards,
        })
    }

    /// Returns the number of data shards as `usize`.
    #[must_use]
    pub const fn k(self) -> usize {
        self.data_shards as usize
    }

    /// Returns the number of parity shards as `usize`.
    #[must_use]
    pub const fn m(self) -> usize {
        self.parity_shards as usize
    }

    /// Returns `k + m` as `usize`.
    #[must_use]
    pub const fn total_shards(self) -> usize {
        self.data_shards as usize + self.parity_shards as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_boundary_values() {
        assert_eq!(FecConfig::new(1, 1).unwrap().total_shards(), 2);
        assert_eq!(FecConfig::new(254, 1).unwrap().total_shards(), 255);
        assert_eq!(FecConfig::new(1, 254).unwrap().total_shards(), 255);
    }

    #[test]
    fn rejects_invalid_values() {
        assert_eq!(FecConfig::new(0, 1), Err(FecError::ZeroDataShards));
        assert_eq!(FecConfig::new(1, 0), Err(FecError::ZeroParityShards));
        assert_eq!(
            FecConfig::new(254, 2),
            Err(FecError::TooManyShards {
                data_shards: 254,
                parity_shards: 2
            })
        );
        assert_eq!(
            FecConfig::new(255, 1),
            Err(FecError::TooManyShards {
                data_shards: 255,
                parity_shards: 1
            })
        );
    }
}
