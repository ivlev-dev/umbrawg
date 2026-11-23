# netlink-packet-umbrawg

[![Crates.io](https://img.shields.io/crates/v/netlink-packet-umbrawg)](https://crates.io/crates/netlink-packet-umbrawg)
[![Docs.rs](https://docs.rs/netlink-packet-umbrawg/badge.svg)](https://docs.rs/netlink-packet-umbrawg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Rust crate for parsing and emitting **Umbra WireGuard** generic netlink packets on Linux.

Версия крейта — `0.4.1` (2026-11-21).

This is a specialized fork focused specifically on **UmbraWG** kernel module support.  
For plain WireGuard, use the original [`netlink-packet-wireguard`](https://crates.io/crates/netlink-packet-wireguard) crate.

## What is UmbraWG?

[UmbraWG](https://github.com/ivlev-dev/umbrawg/tree/master/umbrawg-linux-kernel-module) is a fork of WireGuard that adds junk-packet padding and magic headers to mask WireGuard traffic from Deep Packet Inspection (DPI). This crate allows you to configure UmbraWG interfaces via the kernel netlink API the same way `wg` / `uwg` tools do.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
netlink-packet-umbrawg = "0.4"
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
    .fec(netlink_packet_umbrawg::FecMode::Fixed { k: 8, m: 2 })
    .peer(peer)
    .build()?;
```

Configurations can be parsed back from messages with
`UmbrawgDeviceConfig::from_message` / `UmbrawgPeerConfig::from_peer`,
including the FEC mode.

BBR was removed in 0.5.0. The former attribute numbers
`UWGDEVICE_A_BBR` (36) and `UWGDEVICE_A_BBR_STATS` (39) stay reserved and are
not reused; replies from older kernel modules carrying them are parsed as
unknown attributes and do not fail.

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
| `RandomTrailers(bool)` | `UWGDEVICE_A_RANDOM_TRAILERS` (33): случайный хвост data-пакетов до MTU-бюджета |
| `DisableCookies(bool)` | `UWGDEVICE_A_DISABLE_COOKIES` (34): не отправлять cookie-ответы; rate limit инициаций сохраняется |
| `ExtraPorts(u8)` | `UWGDEVICE_A_EXTRA_PORTS` (35): число дополнительных внешних UDP-портов, `0..=8`, по умолчанию `0` |
| `Fec(u32)` | `UWGDEVICE_A_FEC` (37): `0` off, `1` adaptive, иначе `(K << 8) \| M` с `1 <= K <= 8`, `1 <= M <= 2`. Builders use `FecMode` |
| `UnderlayMtu(u16)` | `UWGDEVICE_A_UNDERLAY_MTU` (40): MTU пути, `576..=65535`, по умолчанию `1500`; при FEC из него выводятся MTU интерфейса и бюджет шарда |
| `FecStats(FecStats)` | `UWGDEVICE_A_FEC_STATS` (38, nested): `blocks_encoded`, `shards_sent`, `blocks_decoded`, `packets_recovered`, `decode_fail`, `dropped_bounds`, `dropped_disabled` |

`FecStats` приходит только в ответе `GET_DEVICE` и не отправляется в
`SET_DEVICE`. `ExtraPorts = 0` — дефолт: один сокет на воркера; включайте
дополнительные порты только в сетях без port-restricted NAT.

BBR удалён в 0.5.0: атрибуты 36 и 39 зарезервированы, а ответы старого ядра
с ними разбираются как неизвестные атрибуты без ошибки.

Partial FEC parity не добавляет netlink-атрибутов: это CAPS-флаг
`FEC_PARTIAL` (бит 4). При включённом FEC обе стороны его анонсируют, и
неполный блок несёт `k' = n`, `m' = m` (data + parity); пир без флага
получает legacy `m' = 0`. RX принимает `k' <= k`, `m' <= m`,
`k' + m' <= k + m` и всегда принимает `m' = 0`.

Peer attributes: `PersistentKeepalive(u16)` is the pre-3.0 wire format, while
UmbraWG 3.0 sends a `u32` (packed `u16` range), parsed into
`PersistentKeepaliveRange(u32)`.
## CI

GitHub Actions runs:

- `deny` job: `cargo deny check --all-features` (dependency policy, `deny.toml`);
- `cargo test --lib` for unit tests (38);
- `cargo test --test builders` (42 builder tests);
- `cargo test --test properties` for the `proptest` suite (15);
- `cargo +nightly fuzz build` to keep both fuzz targets compiling;
- `cargo +nightly fmt --all -- --check` and
  `cargo +nightly clippy --all-targets -- -D warnings`;
- integration tests against a loaded `umbrawg` kernel module (7), with a
  preflight probe that skips the job (with a warning) when the module is
  unavailable;
- `../.github/workflows/netlink-packaging.yml` — Arch package, `.crate`,
  `cargo publish --dry-run` and a GitHub Release on a `netlink-v*` tag.

Integration tests need root, `iproute2`, and the module. A dedicated preflight
job probes `ip link add ... type umbrawg`; if the family is unavailable the
integration job is skipped with an explicit warning instead of silently
passing. The tests themselves also soft-skip when run manually without root,
so use the preflight when you need a trustworthy result.

## Packages and releases

`../.github/workflows/netlink-packaging.yml` builds the distribution artifacts:

| Job | Image | Contents |
|---|---|---|
| `тесты` | `ubuntu-latest` | `cargo test --all-targets` on stable |
| `arch` | `archlinux:latest` | `makepkg -f --noconfirm --nodeps` for `contrib/arch/rust-netlink-packet-umbrawg-git`, then checks `/usr/share/cargo/registry/netlink-packet-umbrawg-<version>/` (`Cargo.toml`, `src/*.rs`, `LICENSE`, `.cargo-checksum.json`) and compiles a probe crate **offline** from that directory through `[source.crates-io] replace-with` |
| `crate` | `ubuntu-latest` | `cargo package --locked`, the `.crate` is uploaded as an artifact |
| `publish dry-run` | `ubuntu-latest` | `cargo publish --dry-run --locked` — catches packaging mistakes without a registry token |
| `релиз` | `ubuntu-latest` | on a `netlink-v*` tag: `.pkg.tar.zst`, `.crate` and `SHA256SUMS` in the GitHub Release |

Release mechanics:

- the tag has to match `netlink-v<version>` from `Cargo.toml`
  (`netlink-v0.4.1` for this release); otherwise the `версия` job fails
  before anything is built;
- `workflow_dispatch` takes an optional `version` input for a manual dry check;
- no secrets are required: nothing is pushed to crates.io or the AUR. Publishing
  the crate stays manual (`cargo publish` with `CARGO_REGISTRY_TOKEN`), and the
  AUR packages are still copied by hand;
- `concurrency` is `packaging-<ref>` for builds (a manual run cancels the
  previous one) and `release-<ref>` for the release job (`cancel-in-progress:
  false`), so two runs never write the same release at once;
- the stable Arch package `contrib/arch/rust-netlink-packet-umbrawg` is **not**
  built in CI: `sha256sums` is the `TODO_UPDPKGSUMS_AFTER_FIRST_TAG` placeholder
  and has to be recalculated with `updpkgsums` after the first tag.

## Документация для разработчика

Состояние проекта и план работ — в [TODO.md](TODO.md).
Порядок выпуска всех четырёх репозиториев (теги, crates.io, AUR, пакеты) —
в [RELEASE.md](https://github.com/ivlev-dev/umbrawg/blob/master/umbrawg-tools/RELEASE.md).

## License

This project is licensed under the [MIT License](./LICENSE).

## Acknowledgements

Based on the original [`netlink-packet-wireguard`](https://github.com/rust-netlink/netlink-packet-wireguard) crate by the rust-netlink team.
