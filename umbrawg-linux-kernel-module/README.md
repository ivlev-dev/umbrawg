# UmbraWG kernel module

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL--2.0-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)

> [!IMPORTANT]
> UmbraWG requires Linux 7.0 or newer. Older kernels are not supported.

Версия в `src/version.h` — `0.4.1` (2026-11-21).

The module uses only the in-kernel cryptography API (`chacha20poly1305`,
`aes-gcm`, `blake2s`, `curve25519`, `chacha`) and builds against the kernel
headers of the running kernel. AES-256-GCM uses Crypto API `gcm(aes)`
(`CONFIG_CRYPTO_GCM`; AES-NI, ARMv8 Crypto Extensions or a hardware driver
such as qce) and falls back to `CONFIG_CRYPTO_LIB_AES_GCM` when `gcm(aes)`
is unavailable. The module selects all of them, and the transport cipher
stays ChaCha20-Poly1305 unless a peer enables AES explicitly.

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
    git clone https://github.com/ivlev-dev/umbrawg.git
    cd umbrawg/umbrawg-linux-kernel-module/src
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
    sudo dkms add -m umbrawg -v 0.4.1
    sudo dkms build -m umbrawg -v 0.4.1
    sudo dkms install -m umbrawg -v 0.4.1
    ```

    > [!NOTE]
    > To verify that a rebuild actually happened, compare the `.ko` timestamp or
    > build log. `srcversion` is not reliable: it does not change when only
    > headers are modified.

## Continuous integration

`.github/workflows/kernel-build.yml` (в корне монорепозитория) catches build
regressions on every push to `master` and `feature/**`, on every pull request,
and on manual `workflow_dispatch`. The workflow runs only when the module
sources or the workflow itself change (`umbrawg-linux-kernel-module/**`,
`.github/workflows/kernel-*.yml`).

| Job | Image | What it does |
|---|---|---|
| `release` | `archlinux:latest` | installs `base-devel git clang llvm lld bc linux-headers kmod`, builds `src/umbrawg.ko`, checks `modinfo` (name and vermagic) and uploads the module with its `modinfo` output |
| `debug` | `archlinux:latest` | builds `make -C src module-debug` with `V=1`, fails on any `warning:`, uploads the full build log |
| `netlink parity` | `archlinux:latest` | builds `uwg` from `umbrawg-tools/` (в том же монорепо, без второго checkout) and runs `src/tests/netlink-parity.sh` if the module can be loaded |
| `FEC profile change` | `archlinux:latest` | loads the built module and runs `src/tests/fec-profile-change.sh`: смена `2:1`/`8:2`/`off`/`adaptive` на ходу, rekey, отсутствие чёрной дыры и `-EINVAL` вне `8:2` |

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

`.github/workflows/kernel-packaging.yml` builds the DKMS packages:

| Job | Image | Contents |
|---|---|---|
| `версия` | `ubuntu-latest` | reads `UMBRAWG_VERSION` from `src/version.h` (`0.4.1`), derives the RPM-safe form (`0.4.1`) and requires the tag to be `kernel-v<version>` |
| `arch` | `archlinux:latest` | `makepkg -f --noconfirm --nodeps` for `contrib/arch/umbrawg-dkms-git`, verifies `/usr/src/umbrawg-<pkgver>/` (`dkms.conf` with `PACKAGE_VERSION` and the `MAKE="make LLVM=1 …"` line, `version.h`, `uapi/umbrawg.h`, sources) and compiles the module from the **packaged** sources |
| `rpm` | `fedora:latest` | builds the source tarball from the checkout, replaces `Version:` in `umbrawg-dkms.spec` with the RPM-safe version, runs `rpmbuild -ba` and checks `rpm -qlp` for the same file set |
| `deb` | `debian:trixie` | `dpkg-buildpackage -b -us -uc` and checks the `/usr/src/umbrawg-*` payload of the `.deb` |
| `релиз` | `ubuntu-latest` | on a `kernel-v*` tag: `.pkg.tar.zst`, `.rpm`, `.deb` and `SHA256SUMS` |

Notes:

- no secrets are needed; nothing is uploaded to the AUR or Copr, both stay
  manual;
- the tag is `kernel-v0.4.1`;
  `workflow_dispatch` accepts an optional `version` input for a manual check;
- the `deb` job installs `dh-dkms` on top of `dkms`: on Debian trixie the
  `--with dkms` debhelper addon is a separate package, without it
  `dpkg-buildpackage` fails in `dh clean`;
- `debian/changelog` и `umbrawg-dkms.spec` несут версию `0.4.1`
  (`0.4.1` в RPM-поле `Version`), поэтому `.deb` называется
  `umbrawg-dkms_0.4.1_all.deb` и ставит
  `/usr/src/umbrawg-0.4.1`; `src/Makefile` и `src/dkms.conf`
  содержат `0.4.1`, упаковщики переопределяют их;
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

### FEC

FEC включён по умолчанию в адаптивном режиме (`fec=adaptive`): на чистом
канале шарды не отправляются, накладных расходов нет и MTU остаётся
базовым, при потерях выше 1% после прогрева включается профиль 2:1, а
после 5 секунд потерь ниже 0.2% он снова выключается. BBR и ACK
удалены в 0.5.0: атрибуты `UWGDEVICE_A_BBR` (36) и
`UWGDEVICE_A_BBR_STATS` (39) сохранены как reserved и отклоняются с
`-EINVAL`, кадр расширения `ACK` (kind 2) игнорируется.

- `uwg set <if> fec off|adaptive|K:M` — `UWGDEVICE_A_FEC` (37, `u32`,
  `(K<<8)|M`); data-plane принимает только `K=1..8`, `M=1..2`, иначе
  `-EINVAL`;
- `uwg set <if> underlay-mtu N` — `UWGDEVICE_A_UNDERLAY_MTU` (40, `u16`,
  576..65535, по умолчанию 1500). При включённом FEC MTU интерфейса
  понижается до `underlay − 132 − S4` (1500 → 1368, при `S4=28` → 1340)
  и восстанавливается при выключении FEC; в adaptive-режиме MTU
  понижается только после того, как FEC реально включился хотя бы на
  одном пире, и пересчитывается отложенно при каждом переключении;
  floor — `min(576, base)`, ручная база ниже 576 не поднимается;
- `uwg show <if> fec-stats` — вложенный `UWGDEVICE_A_FEC_STATS` (38).

Partial FEC parity: при включённом FEC модуль выставляет CAPS-флаг
`FEC_PARTIAL` (бит 4) и для неполного блока шлёт `k' = n`, `m' = m`
(data + parity). Пир без флага получает legacy `m' = 0`. RX принимает
`k' <= k`, `m' <= m`, `k' + m' <= k + m` и всегда принимает `m' = 0`.
Модульный параметр `fec_partial=0` выключает флаг для проверки
совместимости. Формат расширения — в
[`../docs/PROTOCOL-EXT.md`](../docs/PROTOCOL-EXT.md).

## Performance

Measured on 6 vCPU, underlay MTU 9000, TUN MTU 1420, `iperf3` pinned to a
separate CPU, medians of 3 repeats (unified final4 run, 240 cells, 0 failures),
one peer, `obf0`/`obf1` = obfuscation off/on. Kernel module vs `amneziawg`.

| Mode | Profile | `umbrawg` | `amneziawg` |
|---|---|---|---|
| 1 connection | obf0 / obf1 | 2344.6 / 2267.9 | 1871.2 / 1705.1 |
| 3 connections | obf0 / obf1 | 2430.0 / 2252.9 | 1888.0 / 1692.0 |

Mbit/s, TCP, c=1. Gain over `amneziawg`: **+25.3…+33.2%** for a single
connection (obf0/obf1). With 10 connections per client the gain is smaller
(+31.0% 1c, +22.2% 3c on obf0). `go` leads in 3c mode (3.0–4.7 Gbit/s).

One peer is limited by its own threaded NAPI; with work stealing it reaches
**3.08–3.14 Gbit/s TCP** regardless of the number of connections (2.31–2.40
before stealing). Sharding by peers lifts the limit further: four peers reach
**4.99 Gbit/s TCP** (kernel, obf0) / 4.65 (obf1); `go` 4.66 / 4.49; 50 peers
reach **8.25–9.12 Gbit/s** with fairness 1.4–2.2. UDP holds the 1 Gbit/s
line (kernel).

Details, tables and rejected experiments: [docs/PERFORMANCE.md](docs/PERFORMANCE.md).
Full matrix (rust/rust-par, UDP, CPU, multi-peer, e2e):
`umbrawg-tools/docs/RESULTS.md` (final4).

### Per-peer receive sharding

Receive is built around per-peer NAPI: every peer owns a `napi_struct`, an
in-order `rx_queue`, and its own threaded `napi/<dev>-<id>` thread. Capacity
therefore scales with peers, not with connections to one peer; multi-peer
numbers are in [docs/PERFORMANCE.md](docs/PERFORMANCE.md) (final4). The device
has no single shared NAPI; `netif_threaded_enable()` only switches every NAPI
of the device to threaded mode.

The next step is **S2**: the existing per-peer NAPI keeps validation in
arrival order, while a device-level pool of `K <= nCPU` shards does GRO and the
stack work for each flow. Before any S2 code, two cheap checks are mandatory:
a `perf` gate (`Y >= 0.5 * X`) and an RPS probe on `uwg0`. The as-built
contract, per-flow limits, the pool lifecycle, risks and the test plan are in
[docs/PEER-SHARDING.md](docs/PEER-SHARDING.md).

## Limitations

- One peer is limited by its own threaded NAPI (3.08–3.14 Gbit/s TCP with
  work stealing); several connections to the same peer do not add throughput.
  Throughput scales with the number of peers: four peers reach 4.65–4.99
  Gbit/s TCP (final4, obf0/obf1), 50 peers — 8.25–9.12 Gbit/s.
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

## Документация для разработчика

Состояние проекта, измерения и отклонённые эксперименты — в
[TODO.md](TODO.md) и [docs/PERFORMANCE.md](docs/PERFORMANCE.md). Устройство
приёма и разбор отклонённых S1/S2 — в
[docs/PEER-SHARDING.md](docs/PEER-SHARDING.md). Следующий шаг, S3 —
шардирование полного пути пира после replay — в
[docs/PEER-PATH-SHARDING.md](docs/PEER-PATH-SHARDING.md). История версий — в
[CHANGELOG.md](CHANGELOG.md).
Порядок выпуска всех четырёх репозиториев — в
[RELEASE.md](https://github.com/ivlev-dev/umbrawg/blob/master/umbrawg-tools/RELEASE.md).

## License

This project is released under the [GPLv2](COPYING).
