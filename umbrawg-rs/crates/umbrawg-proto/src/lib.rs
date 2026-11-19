//! UmbraWG wire protocol and obfuscation types.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod control;
mod error;
pub mod header_protection;
mod hex;
pub mod messages;
pub mod obf;
pub mod params;
pub mod special;

pub use control::{Ack, Caps, CapsFlags, ControlKind, FecShardHeader};
pub use error::{ProtoError, Result};
pub use messages::{
    CookieReply, HandshakeInitiation, HandshakeResponse, MessageType, TransportPacket,
};
pub use obf::{DetectedPacket, FixedLayout, MessageKind, Obfuscator, TransportLayout};
pub use params::{parse_bool, parse_u16_range, parse_u16_size, parse_u32_range, ObfParams};
pub use special::{SpecialPacket, SpecialPacketContext, Tag};
