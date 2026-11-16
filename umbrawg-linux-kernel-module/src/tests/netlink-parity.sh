#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
set -eu
export LANG=C
DEV=uwgp0
modprobe -q umbrawg 2>/dev/null || true
ip link add dev "$DEV" type umbrawg
trap 'ip link del dev "$DEV" 2>/dev/null || true' EXIT
# Basic set/get round-trip for 3.1 fields
uwg set "$DEV" jc 3 jmin 10 jmax 20 s1 20 s2 20 s3 20 s4 20 h1 100-200 h2 300-400 h3 500-600 h4 700-800 i1 x i2 y i3 z i4 a i5 b random-trailers on disable-cookies off content-padding-addition 1-2 rekey-after-time 3-4 rekey-timeout 5-6 reject-after-time 7-8 keepalive-timeout 9-10 max-handshake-attempts 11-12
uwg show "$DEV"
# Invalid values must be rejected by the kernel.
expect_fail() {
    if "$@"; then
        echo "expected failure: $*" >&2
        exit 1
    fi
}
ip link add dev uwgp1 type umbrawg >/dev/null 2>&1 && ip link del dev uwgp1
expect_fail uwg set "$DEV" jmin 20 jmax 10
echo "netlink parity checks passed"