# UmbraWG kernel module

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL--2.0-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)

> [!IMPORTANT]
> UmbraWG requires Linux 7.0 or newer. Older kernels are not supported.

The module uses only the in-kernel cryptography API (`chacha20poly1305`, `blake2s`, `curve25519`, `chacha`) and builds against the kernel headers of the running kernel.

## Table of contents

- [Installation](#installation)
  - [Ubuntu / Debian / Linux Mint](#ubuntu--debian--linux-mint)
  - [RHEL/CentOS/SUSE/Fedora Core](#rhelcentossusefedora-core)
- [Manual build](#manual-build)
- [Configuration](#configuration)
- [Performance](#performance)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Installation

### Ubuntu / Debian / Linux Mint

Open `Terminal` and proceed with following instructions:

1. (Optionally) Upgrade your system to latest packages including latest available kernel by running `apt-get full-upgrade`.
After kernel upgrade reboot is required.
2. Install pre-requisites - run `sudo apt install -y software-properties-common python3-launchpadlib gnupg2 linux-headers-$(uname -r)`.
3. Install the `umbrawg-dkms` package from the project repository.
4. Finally execute `sudo apt-get install -y umbrawg`.

### RHEL/CentOS/SUSE/Fedora Core

*If you use release that doesn't have DKMS support out of the box, you may need to install [EPEL](https://docs.fedoraproject.org/en-US/epel/#_quickstart) first.*

Open `Terminal` and run:

```shell
sudo dnf copr enable ivlev-dev/umbrawg
sudo dnf install umbrawg-dkms umbrawg-tools
```

Before installation it is strictly recommended to upgrade your system kernel to the latest available version and perform
the reboot afterwards.

## Manual build

You may need to install kernel headers and/or build essentials packages before running following steps.

1. In Terminal:
    ```shell
    git clone https://github.com/ivlev-dev/umbrawg-linux-kernel-module.git
    cd umbrawg-linux-kernel-module/src
    ```

2. Now perform build and installation (use `LLVM=1` if the kernel was built with clang, e.g. Arch/CachyOS):
    ```shell
    make LLVM=1
    sudo make install
    ```

    > [!IMPORTANT]
    > On clang-built kernels `LLVM=1` is mandatory, not optional: a plain `make`
    > fails on compiler flags such as `-fms-anonymous-structs`. Use
    > `make LLVM=1` for every target, including `module-debug`.

    Or on a capable system you may want to use DKMS for this:
    ```shell
    sudo make dkms-install
    sudo dkms add -m umbrawg -v 1.0.0
    sudo dkms build -m umbrawg -v 1.0.0
    sudo dkms install -m umbrawg -v 1.0.0
    ```

    > [!NOTE]
    > To verify that a rebuild actually happened, compare the `.ko` timestamp or
    > build log. `srcversion` is not reliable: it does not change when only
    > headers are modified.

## Configuration

> [!IMPORTANT]
> All parameters must be the same between Client and Server, except for Jc, Jmin, and Jmax - these may vary.

- Jc — 1 ≤ Jc ≤ 128; recommended range is from 4 to 12 inclusive
- Jmin — Jmax > Jmin < 1280*; recommended value is 8
- Jmax — Jmin < Jmax ≤ 1280*; recommended value is 80
- S1 — S1 ≤ 1132* (1280* - 148 = 1132); S1 + 56 ≠ S2; recommended range is from 15 to 150 inclusive
- S2 — S2 ≤ 1188* (1280* - 92 = 1188); recommended range is from 15 to 150 inclusive
- H1/H2/H3/H4 — must be unique among each other; recommended range is from 5 to 2147483647 inclusive

`* Assuming a basic internet connection with an MTU value of 1280.`

## Performance

Measured on 6 vCPU, underlay MTU 9000, TUN MTU 1420, `iperf3` pinned to a
separate CPU, medians of 3–5 repeats, one peer, `obf0`/`obf1` = obfuscation
off/on. Baseline is `master` at `2cd5972`.

| Mode | Profile | `umbrawg` | `amneziawg` |
|---|---|---|---|
| 1 connection | obf0 / obf1 | 2265 / 2167 | 1806 / 1764 |
| 3 connections | obf0 / obf1 | 2032 / 1843 | 1810 / 1716 |

Mbit/s, TCP. The gain over the original implementation is **+13…+25%** for a
single connection, depending on the profile and run-to-run spread — it is not a
fixed +15%. With three connections there is no gain: the difference stays
within the run-to-run spread.

Three connections do not scale because one peer means one outer UDP socket,
one threaded NAPI thread and one in-order queue; only the crypto stage is
actually parallel, and RPS/XPS on veth are disabled in these runs.

Details, rejected experiments and open items: [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

## Limitations

- One peer is served by one outer UDP socket and one threaded NAPI thread.
  Several connections to the same peer do not add throughput; multi-peer
  sharding is still being measured.
- Threaded NAPI cannot be disabled: turning it off costs 11–13% TCP.
- GSO aggregation is part of the send path: the module builds standard UDP GSO
  skbs (up to 23 KB) and the kernel segments them before they hit the wire, so
  no IP fragments are produced. Interoperability with `go`, `rust` and
  `amneziawg` is verified in both directions.
- UDP GRO on the module socket is not implemented (`gro_receive` is `NULL`,
  `ACCEPT_L4` is not set); the estimated gain is 2–4% and it is not a path to
  multi-core scaling.
- Linux 7.0 or newer is required; the in-tree compatibility layer for older
  kernels has been removed.
- UDP loss seen in benchmarks comes from `iperf3` receive-buffer overflow
  (`RcvbufErrors`), not from tunnel drops.

## Troubleshooting

> [!TIP]
> Please check [Ubuntu Server documentation](https://documentation.ubuntu.com/server/how-to/wireguard-vpn/troubleshooting) for more troubleshooting steps.

### Handshake is lost when the kernel starts first

If the kernel side initiates the handshake before the userspace daemon has
bound the UDP port, the first handshake is lost and the tunnel comes up on the
5 second retry. Configure userspace first, then the kernel side.

### Enable debug logging

To get more details, you can enable the dynamic debug feature for the module:

```shell
echo "module umbrawg +p" | sudo tee /sys/kernel/debug/dynamic_debug/control
```

This will log messages to dmesg, which can be watched live with:
```shell
dmesg -wT
```

## License

This project is released under the [GPLv2](COPYING).
