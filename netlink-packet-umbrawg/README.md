# netlink-packet-umbrawg

[![CI](https://github.com/ivlev-dev/netlink-packet-umbrawg/actions/workflows/main.yml/badge.svg)](https://github.com/ivlev-dev/netlink-packet-umbrawg/actions/workflows/main.yml)
[![Crates.io](https://img.shields.io/crates/v/netlink-packet-umbrawg)](https://crates.io/crates/netlink-packet-umbrawg)
[![Docs.rs](https://docs.rs/netlink-packet-umbrawg/badge.svg)](https://docs.rs/netlink-packet-umbrawg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Rust crate for parsing and emitting **Umbra WireGuard** generic netlink packets on Linux.

This is a specialized fork focused specifically on **UmbraWG** kernel module support.  
For plain WireGuard, use the original [`netlink-packet-wireguard`](https://crates.io/crates/netlink-packet-wireguard) crate.

## What is UmbraWG?

[UmbraWG](https://github.com/ivlev-dev/umbrawg-linux-kernel-module) is a fork of WireGuard that adds junk-packet padding and magic headers to mask WireGuard traffic from Deep Packet Inspection (DPI). This crate allows you to configure UmbraWG interfaces via the kernel netlink API the same way `wg` / `uwg` tools do.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
netlink-packet-umbrawg = "0.2"
```

## Quick Start

### Get device info

```rust
use netlink_packet_umbrawg::{
    UmbrawgAttribute, UmbrawgCmd, UmbrawgMessage,
};

let msg = UmbrawgMessage {
    cmd: UmbrawgCmd::GetDevice,
    attributes: vec![UmbrawgAttribute::IfName("uwg0".into())],
};
```

### Set device with Umbra-specific parameters

```rust
use netlink_packet_umbrawg::{
    UmbrawgAddressFamily,
    UmbrawgAllowedIp,
    UmbrawgAllowedIpAttr,
    UmbrawgAttribute,
    UmbrawgCmd,
    UmbrawgMessage,
    UmbrawgPeer,
    UmbrawgPeerAttribute,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

let msg = UmbrawgMessage {
    cmd: UmbrawgCmd::SetDevice,
    attributes: vec![
        UmbrawgAttribute::IfName("uwg0".into()),
        UmbrawgAttribute::ListenPort(51820),
        // UmbraWG-specific junk packet settings
        UmbrawgAttribute::JC(4),
        UmbrawgAttribute::Jmin(40),
        UmbrawgAttribute::Jmax(70),
        UmbrawgAttribute::S1(0x5566),
        UmbrawgAttribute::H1("61220074".into()),
        UmbrawgAttribute::Peers(vec![
            UmbrawgPeer(vec![
                UmbrawgPeerAttribute::PublicKey(peer_pub_key),
                UmbrawgPeerAttribute::Endpoint(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(10, 10, 10, 1)),
                    51820,
                )),
                UmbrawgPeerAttribute::AllowedIps(vec![
                    UmbrawgAllowedIp(vec![
                        UmbrawgAllowedIpAttr::Family(
                            UmbrawgAddressFamily::Ipv4,
                        ),
                        UmbrawgAllowedIpAttr::IpAddr("0.0.0.0".parse().unwrap()),
                        UmbrawgAllowedIpAttr::Cidr(0),
                    ]),
                ]),
            ]),
        ]),
    ],
};
```

### Validated builders

`UmbrawgDeviceConfig` and `UmbrawgPeerConfig` assemble `UWG_CMD_SET_DEVICE`
messages and validate values the way the kernel module does: key lengths,
inverted or overlapping ranges, unsupported flags and the header-protection
padding minimum. Errors are typed (`UmbrawgConfigError`), never panics.

```rust
use std::net::Ipv4Addr;

use netlink_packet_umbrawg::{UmbrawgDeviceConfig, UmbrawgPeerConfig};

let peer = UmbrawgPeerConfig::new([7u8; 32])
    .endpoint_v4(Ipv4Addr::new(10, 0, 0, 1), 51820)
    .persistent_keepalive(25)
    .allowed_ip("0.0.0.0".parse()?, 0)?;

let msg = UmbrawgDeviceConfig::by_name("uwg0")
    .private_key([1u8; 32])
    .listen_port(51820)
    .junk(4, 40, 70)
    .padding(12, 12, 12, 12)
    .h1(61220074, 118999195)
    .header_protection_key([5u8; 32])
    .content_padding_addition(51, 197)
    .random_trailers(true)
    .peer(peer)
    .build()?;
```

Configurations can be parsed back from messages with
`UmbrawgDeviceConfig::from_message` / `UmbrawgPeerConfig::from_peer`.

### Full examples

See the [`examples/`](./examples) directory for complete async programs using `genetlink` and `tokio`.

```bash
cargo run --example get_umbrawg_info -- uwg0
cargo run --example set_umbrawg -- uwg0
```

## Supported attributes

In addition to standard WireGuard attributes (`PrivateKey`, `PublicKey`, `Peers`, `ListenPort`, etc.), the following UmbraWG-specific fields are supported:

| Attribute | Description |
|-----------|-------------|
| `JC` | Junk packet count |
| `Jmin` | Junk packet minimum size |
| `Jmax` | Junk packet maximum size |
| `S1` … `S4` | Junk packet sizes (`u16`) |
| `H1` … `H4` | Magic header specs (`String`, e.g. `"61220074"` or `"684141592-1751861769"`). Emitted as strings for kernel modules up to v1.0 (genl version 2); produced by parsing string payloads |
| `H1Range` … `H4Range` | Magic headers as packed `u64` ranges (`lo \| hi << 32`), the UmbraWG 3.0 wire format (genl version 3). Use `range::u32_range_from_string` to build them from spec strings; produced by parsing 8-byte payloads |
| `H1Legacy` … `H4Legacy` | Magic headers as bare `u32`, the original module format (genl version 1); produced by parsing 4-byte payloads |
| `I1` … `I5` | Intermediate header descriptors (`String`)|
| `HeaderProtectionKey` | UmbraWG 3.0 header protection key (32 bytes) |
| `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts` | UmbraWG 3.0 tuning knobs (`u32`) |

Peer attributes: `PersistentKeepalive(u16)` is the pre-3.0 wire format, while
UmbraWG 3.0 sends a `u32` (packed `u16` range), parsed into
`PersistentKeepaliveRange(u32)`.
## CI

GitHub Actions runs:

- `cargo test --lib` for unit tests;
- `cargo test --test properties` for the `proptest` suite;
- `cargo +nightly fuzz build` to keep both fuzz targets compiling;
- `cargo +nightly fmt --all -- --check` and
  `cargo +nightly clippy --all-targets -- -D warnings`;
- integration tests against a loaded `umbrawg` kernel module.

Integration tests need root, `iproute2`, and the module. A dedicated preflight
job probes `ip link add ... type umbrawg`; if the family is unavailable the
integration job is skipped with an explicit warning instead of silently
passing. The tests themselves also soft-skip when run manually without root,
so use the preflight when you need a trustworthy result.

## License

This project is licensed under the [MIT License](./LICENSE).

## Acknowledgements

Based on the original [`netlink-packet-wireguard`](https://github.com/rust-netlink/netlink-packet-wireguard) crate by the rust-netlink team.
