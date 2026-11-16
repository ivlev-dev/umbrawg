// SPDX-License-Identifier: MIT

//! The `netlink-packet-umbrawg` crate is designed for parsing and
//! emitting generic netlink packets for Umbra WireGuard interface.

pub mod constants;
pub mod range;

mod allowedip;
mod attribute;
mod message;
mod peer;
mod socket_addr;

#[cfg(test)]
mod test;

pub use self::{
    allowedip::{
        UmbrawgAddressFamily, UmbrawgAllowedIp,
        UmbrawgAllowedIpAttr,
    },
    attribute::UmbrawgAttribute,
    message::{UmbrawgCmd, UmbrawgMessage},
    peer::{
        UmbrawgPeer, UmbrawgPeerAttribute,
        UmbrawgTimeSpec,
    },
};
