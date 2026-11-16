//! UmbraWG UDP transport: socket wrapper, batching, GSO/GRO and sticky sockets.
//!
//! The crate is deliberately thin and allocation-free on the data path:
//!
//! * [`Socket`] opens a non-blocking IPv4 or IPv6 (optionally dual-stack) UDP
//!   socket and applies `SO_MARK`, `SO_BINDTODEVICE`, buffer sizes and path MTU
//!   discovery.
//! * [`RecvQueue`] and [`SendQueue`] own the `recvmmsg`/`sendmmsg` scratch space,
//!   so [`Socket::recv_batch`] and [`Socket::send_batch`] never allocate.
//! * [`Outgoing::segmented`] marks a super-datagram for `UDP_SEGMENT`; received
//!   `UDP_GRO` metadata is reported through [`RecvMeta::gro_size`].
//! * [`GsoLimits`], [`GsoLayout`], [`split_into_segments`] and [`coalesce_into`]
//!   implement the segment arithmetic used by the device and TUN layers.
//!
//! Sticky sockets are supported at the control-message level: [`SourceAddr`]
//! carries `IP_PKTINFO`/`IPV6_PKTINFO` and [`Endpoint`] keeps it next to the
//! destination address.
//!
//! ```no_run
//! use std::net::SocketAddr;
//! use umbrawg_transport::{Endpoint, OpenOptions, Outgoing, SendQueue, Socket, AddressFamily};
//!
//! # fn main() -> umbrawg_transport::Result<()> {
//! let socket = Socket::open(OpenOptions::new(AddressFamily::Ipv4))?;
//! let mut queue = SendQueue::new(8)?;
//! let endpoint = Endpoint::new("192.0.2.1:51820".parse::<SocketAddr>().unwrap());
//! let payload = [0u8; 128];
//! socket.send_batch(&mut queue, endpoint, &[Outgoing::new(&payload)])?;
//! # Ok(())
//! # }
//! ```

#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_os = "linux"))]
compile_error!(
    "umbrawg-transport currently supports Linux only; Windows and BSD backends are not implemented"
);

mod addr;
mod batch;
mod cmsg;
mod consts;
mod error;
mod gso;
mod socket;
mod sticky;
mod sys;

pub use addr::{AddressFamily, Endpoint, normalize_ipv4_mapped};
pub use batch::{Outgoing, RecvMeta, RecvQueue, SendQueue};
pub use cmsg::{CmsgWriter, ControlBuffer, ControlMessage, ControlMessages, gro_size, gso_size};
pub use error::{Result, TransportError};
pub use gso::{
    DEFAULT_MTU, GsoLayout, GsoLimits, GsoSize, IPV4_HEADER_LEN, IPV6_HEADER_LEN, MAX_SEGMENTS,
    MAX_UDP_PAYLOAD_V4, MAX_UDP_PAYLOAD_V6, UDP_HEADER_LEN, coalesce_into, segment_count,
    split_into_segments,
};
pub use socket::{Features, Incoming, MtuDiscover, OpenOptions, Socket, interface_mtu};
pub use sticky::SourceAddr;

/// Maximum number of datagrams handled by one batch call.
///
/// This matches the kernel's `udpSegmentMaxDatagrams` limit, which also bounds
/// the number of segments inside a single `UDP_SEGMENT` super-datagram.
pub const MAX_BATCH_SIZE: usize = MAX_SEGMENTS;
