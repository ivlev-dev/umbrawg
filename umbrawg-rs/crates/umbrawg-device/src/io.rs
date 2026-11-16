use std::net::SocketAddr;
use std::time::Instant;

use rand_core::RngCore;

use crate::peer::Peer;

pub trait DatagramSink {
    fn send_datagram(
        &mut self,
        endpoint: SocketAddr,
        peer: Option<&Peer>,
        payload: &[u8],
        gso_size: Option<usize>,
    );
}

pub trait PacketIo: DatagramSink {
    fn deliver(&mut self, peer: &Peer, packet: &[u8]);
}

pub struct IoContext<'a, R: RngCore, S: DatagramSink> {
    pub rng: &'a mut R,
    pub now: Instant,
    pub scratch: &'a mut [u8],
    pub io: &'a mut S,
}

impl<'a, R: RngCore, S: DatagramSink> IoContext<'a, R, S> {
    #[must_use]
    pub fn new(rng: &'a mut R, now: Instant, scratch: &'a mut [u8], io: &'a mut S) -> Self {
        Self {
            rng,
            now,
            scratch,
            io,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncomingMeta {
    pub source: SocketAddr,
    pub gro_size: Option<usize>,
}

impl IncomingMeta {
    #[must_use]
    pub const fn new(source: SocketAddr, gro_size: Option<usize>) -> Self {
        Self { source, gro_size }
    }

    #[must_use]
    pub const fn datagram(source: SocketAddr) -> Self {
        Self {
            source,
            gro_size: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncomingOutcome {
    Delivered(usize),
    Keepalive,
    Handshake,
    Cookie,
    Dropped,
}

impl IncomingOutcome {
    #[must_use]
    pub const fn is_dropped(self) -> bool {
        matches!(self, Self::Dropped)
    }
}
