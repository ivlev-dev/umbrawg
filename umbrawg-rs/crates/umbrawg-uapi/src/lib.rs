//! UmbraWG UAPI server.
//!
//! The crate implements the WireGuard-compatible control protocol used by
//! `uwg` and the Go daemon:
//!
//! * a Unix-domain listener at `/var/run/umbrawg/<iface>.sock` protected by
//!   file permissions and `SO_PEERCRED`;
//! * a parser for `set=1` requests, including the UmbraWG 3.1 obfuscation
//!   parameters;
//! * a serializer for `get=1` replies that is byte-compatible with the Go
//!   implementation and with `umbrawg-ctl`.
//!
//! The control plane talks to the device through [`DeviceControl`], so the
//! UAPI crate has no dependency on the device implementation.

#![deny(missing_docs)]

mod error;
mod parse;
mod protocol;
mod serialize;
mod types;

#[cfg(unix)]
mod listener;

pub use error::UapiError;
pub use parse::parse_set_request;
pub use serialize::{format_errno, format_errno_response, format_get_response};
pub use types::{
    max_prefix_len, validate_obfuscation_update, AllowedIp, AllowedIpChange, BbrStats, Cipher,
    DeviceControl, DeviceSnapshot, FecStats, ObfuscationRequest, ObfuscationSnapshot, PeerRequest,
    PeerSnapshot, SetRequest, SpecialPacketUpdate, TimingRequest, TimingSnapshot, U16Range,
    U32Range, ValueError, DEFAULT_UNDERLAY_MTU, MIN_UNDERLAY_MTU,
};

#[cfg(unix)]
pub use listener::{
    socket_dir, socket_path, socket_path_in, validate_interface_name, ServerHandle, UapiListener,
    DEFAULT_SOCKET_DIR, SOCKET_SUFFIX,
};
