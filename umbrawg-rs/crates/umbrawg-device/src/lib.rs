//! UmbraWG device and peer state machine.

#![forbid(unsafe_code)]

pub mod allowedips;
pub mod buffer;
mod control;
pub mod device;
pub mod error;
pub mod gso;
pub mod index;
pub mod io;
pub mod keypair;
mod obf;
pub mod peer;
pub mod ratelimiter;
pub mod replay;
pub mod timers;

pub use allowedips::{AllowedIp, AllowedIpEntry, AllowedIps, PeerId};
pub use buffer::{Buffer, BufferPool, DEFAULT_BUFFER_SIZE};
pub use device::{Device, DeviceConfig, SendOutcome, TimerEvent};
pub use error::{DeviceError, Result};
pub use gso::{BatchLayout, GsoGroup, GroSegments, MAX_GSO_GROUPS, MAX_GSO_SEGMENTS};
pub use index::{IndexEntry, IndexTable};
pub use io::{DatagramSink, IncomingMeta, IncomingOutcome, IoContext, PacketIo};
pub use keypair::{Keypair, Keypairs, RemovedIndexes};
pub use peer::{Peer, PeerConfig, PeerState};
pub use ratelimiter::RateLimiter;
pub use replay::{ReplayFilter, REPLAY_WINDOW_BITS};
pub use timers::{Range16, TimerKind, Timers, Timings, TIMER_COUNT};
pub use umbrawg_uapi::{
    AllowedIpChange, DeviceControl, DeviceSnapshot, ObfuscationRequest, ObfuscationSnapshot,
    PeerRequest, PeerSnapshot, SetRequest, SpecialPacketUpdate, TimingRequest, TimingSnapshot,
};

pub const DEFAULT_MTU: u16 = 1420;
