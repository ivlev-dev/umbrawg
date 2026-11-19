use core::fmt;

/// Errors produced while configuring, encoding or decoding FEC blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FecError {
    /// `data_shards` must be at least 1.
    ZeroDataShards,
    /// `parity_shards` must be at least 1.
    ZeroParityShards,
    /// `data_shards + parity_shards` exceeds [`super::MAX_TOTAL_SHARDS`].
    TooManyShards {
        /// Requested number of data shards.
        data_shards: u8,
        /// Requested number of parity shards.
        parity_shards: u8,
    },
    /// A packet does not fit into a shard after the 2-byte length prefix.
    PacketTooLarge {
        /// Size of the rejected packet in bytes.
        packet_len: usize,
        /// Maximum shard payload configured for the encoder.
        max_shard_len: usize,
    },
    /// A shard index is outside `0..k+m`.
    InvalidIndex {
        /// Rejected shard index.
        index: u8,
        /// Number of data shards carried by the shard.
        k: u8,
        /// Number of parity shards carried by the shard.
        m: u8,
    },
    /// A shard length is too small to hold the 2-byte packet length prefix.
    InvalidShardLen {
        /// Rejected shard length.
        shard_len: u16,
    },
    /// The payload length does not match the advertised shard length.
    PayloadLenMismatch {
        /// Advertised shard length.
        expected: u16,
        /// Actual payload length.
        actual: usize,
    },
    /// The length prefix of a data shard exceeds the shard capacity.
    InvalidPacketLen {
        /// Length advertised by the shard prefix.
        packet_len: u16,
        /// Shard length that bounds the packet.
        shard_len: u16,
    },
    /// Shard parameters disagree with the decoder configuration or the block.
    ConfigMismatch {
        /// Configured number of data shards.
        expected_k: u8,
        /// Configured number of parity shards.
        expected_m: u8,
        /// Number of data shards carried by the shard.
        actual_k: u8,
        /// Number of parity shards carried by the shard.
        actual_m: u8,
    },
    /// A shard length differs from the first shard of the same block.
    ShardLenMismatch {
        /// Block identifier.
        block_id: u32,
        /// Shard length established by the first shard of the block.
        expected: u16,
        /// Shard length of the rejected shard.
        actual: u16,
    },
}

impl fmt::Display for FecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDataShards => formatter.write_str("data_shards must be at least 1"),
            Self::ZeroParityShards => formatter.write_str("parity_shards must be at least 1"),
            Self::TooManyShards {
                data_shards,
                parity_shards,
            } => write!(
                formatter,
                "k + m = {data_shards} + {parity_shards} exceeds 255"
            ),
            Self::PacketTooLarge {
                packet_len,
                max_shard_len,
            } => write!(
                formatter,
                "packet of {packet_len} bytes does not fit into max_shard_len {max_shard_len}"
            ),
            Self::InvalidIndex { index, k, m } => {
                write!(
                    formatter,
                    "shard index {index} is outside 0..{}",
                    u16::from(*k) + u16::from(*m)
                )
            }
            Self::InvalidShardLen { shard_len } => {
                write!(formatter, "shard length {shard_len} is smaller than 2")
            }
            Self::PayloadLenMismatch { expected, actual } => {
                write!(
                    formatter,
                    "payload length {actual} does not match shard_len {expected}"
                )
            }
            Self::InvalidPacketLen {
                packet_len,
                shard_len,
            } => write!(
                formatter,
                "packet length {packet_len} exceeds shard capacity {}",
                shard_len.saturating_sub(2)
            ),
            Self::ConfigMismatch {
                expected_k,
                expected_m,
                actual_k,
                actual_m,
            } => write!(
                formatter,
                "shard k/m {actual_k}/{actual_m} does not match expected {expected_k}/{expected_m}"
            ),
            Self::ShardLenMismatch {
                block_id,
                expected,
                actual,
            } => write!(
                formatter,
                "block {block_id} shard_len {actual} does not match {expected}"
            ),
        }
    }
}

impl std::error::Error for FecError {}
