//! Linux TUN device with multi-queue and virtio-net offload support.
//!
//! The crate exposes a [`Tun`] queue with batched reads and writes, GSO packet
//! splitting on receive, optional GRO-ready virtio headers on transmit, MTU
//! management, and raw file descriptors suitable for `poll(2)`.

#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

mod error;
mod offload;
mod virtio;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(not(target_os = "linux"))]
compile_error!(
    "umbrawg-tun currently supports Linux only; Android and iOS TUN backends are not implemented"
);

pub use error::{TunError, TunResult};
pub use offload::{
    gso_none_checksum, gso_segment_count, gso_segment_len, max_gso_segments, max_gso_size,
    packet_buffer_size, prepare_gso, read_buffer_size, split_gso, GsoError, MAX_PACKET_SIZE,
};
#[cfg(target_os = "linux")]
pub use linux::{
    Offload, Tun, TunConfig, TunSet, IDEAL_BATCH_SIZE, TUN_DEVICE_PATH,
};
pub use virtio::{
    GsoType, VirtioNetHdr, VIRTIO_NET_HDR_F_DATA_VALID, VIRTIO_NET_HDR_F_NEEDS_CSUM,
    VIRTIO_NET_HDR_GSO_ECN, VIRTIO_NET_HDR_GSO_NONE, VIRTIO_NET_HDR_GSO_TCPV4,
    VIRTIO_NET_HDR_GSO_TCPV6, VIRTIO_NET_HDR_GSO_UDP, VIRTIO_NET_HDR_GSO_UDP_L4,
};
