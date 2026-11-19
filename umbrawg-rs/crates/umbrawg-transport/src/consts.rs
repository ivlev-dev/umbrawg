//! Linux UAPI constants that are not exposed by the `libc` crate for every target.

use libc::c_int;

/// `IPPROTO_UDP`, the protocol level used for UDP offload control messages.
pub(crate) const SOL_UDP: c_int = libc::IPPROTO_UDP;

/// `UDP_SEGMENT` (Linux 4.18+): sets the GSO segment size of outgoing datagrams.
pub(crate) const UDP_SEGMENT: c_int = 103;

/// `UDP_GRO` (Linux 5.12+): enables receive offload and reports the segment size.
pub(crate) const UDP_GRO: c_int = 104;

/// `SO_MARK`: attaches a routing mark (`fwmark`) to the socket.
pub(crate) const SO_MARK: c_int = 36;

/// `SO_BINDTODEVICE`: pins the socket to a single network interface.
pub(crate) const SO_BINDTODEVICE: c_int = 25;

/// `SIOCGIFMTU`: reads the MTU of an interface.
pub(crate) const SIOCGIFMTU: libc::c_ulong = 0x8921;

/// `IP_MTU_DISCOVER` (Linux `IPPROTO_IP` option).
pub(crate) const IP_MTU_DISCOVER: c_int = 10;

/// `IPV6_MTU_DISCOVER` (Linux `IPPROTO_IPV6` option).
pub(crate) const IPV6_MTU_DISCOVER: c_int = 23;

/// `IP_PMTUDISC_DONT`: never send DF and accept local fragmentation.
pub(crate) const IP_PMTUDISC_DONT: c_int = 0;

/// `IP_PMTUDISC_WANT`: use DF when the route requires it.
pub(crate) const IP_PMTUDISC_WANT: c_int = 1;

/// `IP_PMTUDISC_DO`: always send DF.
pub(crate) const IP_PMTUDISC_DO: c_int = 2;

/// `IP_PMTUDISC_PROBE`: always send DF, ignoring the route MTU.
pub(crate) const IP_PMTUDISC_PROBE: c_int = 3;

/// `IP_PMTUDISC_OMIT`: never send DF, let fragmentation be local.
pub(crate) const IP_PMTUDISC_OMIT: c_int = 5;

/// Size of the control buffer used for GSO/GRO and sticky address metadata.
///
/// One `IPV6_PKTINFO` message needs 40 bytes on 64-bit targets and 32 on
/// 32-bit targets; a `UDP_SEGMENT` message needs 24 and 16 bytes respectively.
pub(crate) const CONTROL_BUFFER_SIZE: usize = 128;
