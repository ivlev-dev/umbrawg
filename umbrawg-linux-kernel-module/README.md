# UmbraWG kernel module

> [!IMPORTANT]
> UmbraWG requires Linux 7.0 or newer. Older kernels are not supported.

The module uses only the in-kernel cryptography API (`chacha20poly1305`, `blake2s`, `curve25519`, `chacha`) and builds against the kernel headers of the running kernel.

## Table of contents

- [Installation](#installation)
  - [Ubuntu / Debian / Linux Mint](#ubuntu--debian--linux-mint)
  - [RHEL/CentOS/SUSE/Fedora Core](#rhelcentossusefedora-core)
- [Manual build](#manual-build)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Installation

### Ubuntu / Debian / Linux Mint

Open `Terminal` and proceed with following instructions:

1. (Optionally) Upgrade your system to latest packages including latest available kernel by running `apt-get full-upgrade`.
After kernel upgrade reboot is required.
2. Install pre-requisites - run `sudo apt install -y software-properties-common python3-launchpadlib gnupg2 linux-headers-$(uname -r)`.
3. Run `sudo add-apt-repository ppa:amnezia/ppa`.
4. Finally execute `sudo apt-get install -y umbrawg`.

### RHEL/CentOS/SUSE/Fedora Core

*If you use release that doesn't have DKMS support out of the box, you may need to install [EPEL](https://docs.fedoraproject.org/en-US/epel/#_quickstart) first.*

Open `Terminal` and run:

```shell
sudo dnf copr enable amneziavpn/amneziawg
sudo dnf install umbrawg-dkms umbrawg-tools
```

Before installation it is strictly recommended to upgrade your system kernel to the latest available version and perform
the reboot afterwards.

## Manual build

You may need to install kernel headers and/or build essentials packages before running following steps.

1. In Terminal:
    ```shell
    git clone https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git
    cd umbrawg-linux-kernel-module/src
    ```

2. Now perform build and installation:
    ```shell
    make
    sudo make install
    ```

    Or on a capable system you may want to use DKMS for this:
    ```shell
    sudo make dkms-install
    sudo dkms add -m umbrawg -v 1.0.0
    sudo dkms build -m umbrawg -v 1.0.0
    sudo dkms install -m umbrawg -v 1.0.0
    ```

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

## Troubleshooting

> [!TIP]
> Please check [Ubuntu Server documentation](https://documentation.ubuntu.com/server/how-to/wireguard-vpn/troubleshooting) for more troubleshooting steps.

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
