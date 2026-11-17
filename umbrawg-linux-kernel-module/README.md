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
- [Continuous integration](#continuous-integration)
- [Packages and releases](#packages-and-releases)
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

## Continuous integration

`.github/workflows/build.yml` catches build regressions on every push to
`master` and `feature/**`, on every pull request, and on manual
`workflow_dispatch`. The workflow runs only when the module sources or the
workflow itself change (`src/**`, `Makefile`, `Kbuild`, `Kconfig`,
`.github/workflows/build.yml`).

| Job | Image | What it does |
|---|---|---|
| `release` | `archlinux:latest` | installs `base-devel git clang llvm lld bc linux-headers kmod`, builds `src/umbrawg.ko`, checks `modinfo` (name and vermagic) and uploads the module with its `modinfo` output |
| `debug` | `archlinux:latest` | builds `make -C src module-debug` with `V=1`, fails on any `warning:`, uploads the full build log |
| `netlink parity` | `archlinux:latest` | checks out `ivlev-dev/umbrawg-tools` and `ivlev-dev/netlink-packet-umbrawg` next to the module, builds `uwg`, and runs `src/tests/netlink-parity.sh` if the module can be loaded |

Requirements and behaviour:

- the jobs need no secrets and use `permissions: contents: read`; each job has
  a 40-minute timeout;
- the kernel headers come from the container's `linux-headers` package, so the
  build target is the Arch kernel, not the GitHub runner kernel. The workflow
  locates the headers in `/usr/lib/modules/*/build` and passes `KERNELDIR`
  explicitly, because `uname -r` inside the container is the runner kernel;
- the compiler is detected from the headers, not hardcoded. The workflow checks
  `CONFIG_CC_IS_CLANG` in `.config` (with `include/config/auto.conf` as a
  fallback): clang-built kernels are built with `make LLVM=1`, GCC-built kernels
  (including Arch's stock kernel) are built with a plain `make`. A GCC-built
  kernel rejects the flags used by clang and vice versa, so both release and
  debug builds follow the kernel's compiler;
- the expected module version is read from `src/version.h` and passed as
  `UMBRAWG_VERSION`, the same way the DKMS packages do it;
- the parity script needs a loaded `umbrawg` module and root. In a container the
  built module targets the Arch kernel, which normally differs from the runner
  kernel, and module loading may require `CAP_SYS_MODULE`. When either check
  fails, the job emits a `::warning::` annotation and a summary entry saying
  that parity was skipped; the script is never reported as passed silently.
  The `uwg` build itself always runs and fails the job on a build error;
- the `release` and `debug` jobs were verified locally in Docker
  (`archlinux:latest`), and the `parity` job was verified up to the expected
  skip; `actionlint` reports 0 findings.

## Packages and releases

`.github/workflows/packaging.yml` builds the DKMS packages:

| Job | Image | Contents |
|---|---|---|
| `версия` | `ubuntu-latest` | reads `UMBRAWG_VERSION` from `src/version.h` (`3.1.20261113-02`), derives the RPM-safe form (`3.1.20261113_02`) and requires the tag to be `v<version>` |
| `arch` | `archlinux:latest` | `makepkg -f --noconfirm --nodeps` for `contrib/arch/umbrawg-dkms-git`, verifies `/usr/src/umbrawg-<pkgver>/` (`dkms.conf` with `PACKAGE_VERSION` and the `MAKE="make LLVM=1 …"` line, `version.h`, `uapi/umbrawg.h`, sources) and compiles the module from the **packaged** sources |
| `rpm` | `fedora:latest` | builds the source tarball from the checkout, replaces `Version:` in `umbrawg-dkms.spec` with the RPM-safe version, runs `rpmbuild -ba` and checks `rpm -qlp` for the same file set |
| `deb` | `debian:trixie` | `dpkg-buildpackage -b -us -uc` and checks the `/usr/src/umbrawg-*` payload of the `.deb` |
| `релиз` | `ubuntu-latest` | on a `v*` tag: `.pkg.tar.zst`, `.rpm`, `.deb` and `SHA256SUMS` |

Notes:

- no secrets are needed; nothing is uploaded to the AUR or Copr, both stay
  manual;
- the tag must be `v3.1.20261113-02` (no tag exists yet). `workflow_dispatch`
  accepts an optional `version` input for a manual check;
- the `deb` job installs `dh-dkms` on top of `dkms`: on Debian trixie the
  `--with dkms` debhelper addon is a separate package, without it
  `dpkg-buildpackage` fails in `dh clean`;
- `debian/changelog` still says `1.0.0`, so the `.deb` is named
  `umbrawg-dkms_1.0.0_all.deb` and ships `/usr/src/umbrawg-1.0.0`. The job emits a
  warning when this version differs from `src/version.h`; bump the changelog
  before a real release (the RPM uses the version from `version.h` instead);
- the DKMS packages ship sources only, so building them on the target machine
  needs kernel headers (`linux-headers`, `kernel-devel`, `linux-headers-$(uname -r)`)
  and a toolchain; `dkms` is the only hard dependency;
- `LLVM=1` is mandatory only for kernels built with clang (CachyOS, some Fedora
  builds). Arch's stock kernel is GCC-built, so the `arch` job picks the flag
  based on `CONFIG_CC_IS_CLANG` in the installed headers and builds with the same
  compiler as the kernel;
- the stable Arch package `contrib/arch/umbrawg-dkms` is not built in CI: its
  `sha256sums` is the `TODO_UPDPKGSUMS_AFTER_FIRST_TAG` placeholder and needs
  `updpkgsums` after the first tag;
- jobs are verified locally in Docker (Arch, Fedora, Debian), not yet in GitHub
  Actions.

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

`master` also includes crypto-wakeup coalescing (`03654de`, merged as
`f0333de`): `queue_work_on` runs only on the `0 → 1` transition of the pending
flag. It is safe and gives **+2…+4%** on CPU-bound single-stream TCP and about
+1% on UDP capacity, while the aggregate effect over the whole matrix is near
zero — an incidental optimization, not the path to multi-core scaling.

| Mode | Profile | `umbrawg` | `amneziawg` |
|---|---|---|---|
| 1 connection | obf0 / obf1 | 2265 / 2167 | 1806 / 1764 |
| 3 connections | obf0 / obf1 | 2032 / 1843 | 1810 / 1716 |

Mbit/s, TCP. The gain over the original implementation is **+13…+25%** for a
single connection, depending on the profile and run-to-run spread — it is not a
fixed +15%. With three connections there is no gain on one peer: the difference
stays within the run-to-run spread.

One peer is limited by its own threaded NAPI at **~2.2–2.4 Gbit/s TCP**,
regardless of the number of connections. Sharding by peers lifts the limit:
four peers reach **4.1–4.8 Gbit/s TCP** (+146…+178%), both with four outer
sockets and with a single socket on the server. UDP plateaus at ~3.6 Gbit/s,
limited by softirq and the application.

Details, tables and rejected experiments: [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

## Limitations

- One peer is limited by its own threaded NAPI (~2.2–2.4 Gbit/s TCP); several
  connections to the same peer do not add throughput. Throughput scales with
  the number of peers: four peers reach 4.1–4.8 Gbit/s TCP.
- Threaded NAPI cannot be disabled: turning it off costs 11–13% TCP.
- GSO aggregation is part of the send path: the module builds standard UDP GSO
  skbs (up to 23 KB) and the kernel segments them before they hit the wire, so
  no IP fragments are produced. Interoperability with `go`, `rust` and
  `amneziawg` is verified in both directions.
- UDP GRO on the module socket is not implemented (`gro_receive` is `NULL`,
  `ACCEPT_L4` is not set); the estimated gain for a single peer is 2–4% and
  remains a hypothesis. It does not address multi-peer scaling.
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
