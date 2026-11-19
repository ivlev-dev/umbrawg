//! Packet-level systematic Reed-Solomon FEC for UmbraWG.
//!
//! The crate implements the FEC part of the UmbraWG protocol extension
//! (`docs/PROTOCOL-EXT.md`, section 4): packets are grouped into blocks of
//! `k` data shards, protected by `m` parity shards over `GF(256)` with the
//! `0x11d` polynomial. The code is systematic, so a block is transmitted as
//! `k` data shards followed by `m` parity shards, and any `k` of the `k + m`
//! shards are sufficient to recover the original packets.
//!
//! [`FecEncoder`] accumulates packets and emits [`EncodedBlock`] values.
//! [`FecDecoder`] collects received [`FecShard`] values, restores lost data
//! shards and returns [`DecodedBlock`] values in block order.
//!
//! # Example
//!
//! ```
//! use umbrawg_fec::{FecConfig, FecDecoder, FecEncoder, FecShard};
//!
//! let config = FecConfig::new(4, 2).unwrap();
//! let mut encoder = FecEncoder::new(config, 1500);
//! let packets: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8; 32]).collect();
//!
//! let mut block = None;
//! for packet in &packets {
//!     block = encoder.push(packet).unwrap().or(block);
//! }
//! let block = block.expect("four packets fill the block");
//! assert_eq!(block.shards.len(), 6);
//!
//! let mut decoder = FecDecoder::new(config);
//! let now = std::time::Instant::now();
//! let mut decoded = Vec::new();
//! for (index, payload) in block.shards.iter().enumerate().skip(1) {
//!     let shard = FecShard {
//!         block_id: block.block_id,
//!         index: index as u8,
//!         k: block.k,
//!         m: block.m,
//!         shard_len: block.shard_len,
//!         payload,
//!     };
//!     decoded.extend(decoder.push_at(shard, now).unwrap());
//! }
//!
//! assert_eq!(decoded.len(), 1);
//! assert_eq!(decoded[0].packets, packets);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod config;
mod decoder;
mod encoder;
mod error;
mod gf;
mod matrix;

use core::time::Duration;

pub use config::FecConfig;
pub use decoder::{DecodedBlock, FecDecoder, FecShard};
pub use encoder::{EncodedBlock, FecEncoder};
pub use error::FecError;

/// Maximum number of shards in one Reed-Solomon block (`k + m`).
pub const MAX_TOTAL_SHARDS: usize = 255;

/// Default time the decoder waits for missing shards before releasing a block.
pub const DEFAULT_BLOCK_TIMEOUT: Duration = Duration::from_millis(5);
