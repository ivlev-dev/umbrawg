#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: test-userspace.sh requires root" >&2
    exit 1
fi

IFACE="${IFACE:-uwg0}"
UWG_BIN="${UWG_BIN:-/root/umbrawg/tools/target/debug/uwg}"
DAEMON="${DAEMON:-/root/umbrawg/rust/umbrawg}"

if [ ! -x "$UWG_BIN" ]; then
    for candidate in uwg /root/umbrawg/tools/target/release/uwg; do
        if command -v "$candidate" >/dev/null 2>&1; then
            UWG_BIN="$(command -v "$candidate")"
            break
        fi
    done
fi
if [ ! -x "$UWG_BIN" ]; then
    echo "SKIP: uwg binary not found" >&2
    exit 0
fi
if [ ! -x "$DAEMON" ]; then
    echo "SKIP: userspace daemon binary not found: $DAEMON" >&2
    exit 0
fi

TMPDIR="$(mktemp -d)"
SOCK="/var/run/umbrawg/$IFACE.sock"
cleanup() {
    set +e
    if [ -n "${DAEMON_PID:-}" ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    ip link del "$IFACE" 2>/dev/null || true
    rm -f "$SOCK" 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

PRIV="$("$UWG_BIN" genkey)"
PEER_PRIV="$("$UWG_BIN" genkey)"
PEER_PUB="$(printf '%s\n' "$PEER_PRIV" | "$UWG_BIN" pubkey)"
CFG="$TMPDIR/test.conf"
cat >"$CFG" <<EOF
[Interface]
PrivateKey = $PRIV
ListenPort = 51821

[Peer]
PublicKey = $PEER_PUB
AllowedIPs = 10.99.0.0/24
EOF

echo "== start userspace daemon =="
"$DAEMON" -f "$IFACE" >"$TMPDIR/daemon.log" 2>&1 &
DAEMON_PID=$!

for i in $(seq 1 50); do
    [ -S "$SOCK" ] && break
    sleep 0.1
done
if [ ! -S "$SOCK" ]; then
    if grep -q "first class support" "$TMPDIR/daemon.log" 2>/dev/null; then
        echo "SKIP: userspace daemon is not usable because kernel module is loaded" >&2
        exit 0
    fi
    echo "ERROR: daemon socket did not appear: $SOCK" >&2
    cat "$TMPDIR/daemon.log" >&2 || true
    exit 1
fi

echo "== uwg show (userspace) =="
"$UWG_BIN" show "$IFACE"

echo "== uwg setconf (userspace, all available fields) =="
if [ -f "$CFG" ]; then
    "$UWG_BIN" setconf "$IFACE" "$CFG"
fi

echo "== idempotent setconf check =="
before="$("$UWG_BIN" showconf "$IFACE")"
if [ -f "$CFG" ]; then
    "$UWG_BIN" setconf "$IFACE" "$CFG"
fi
after="$("$UWG_BIN" showconf "$IFACE")"
if [ "$before" != "$after" ]; then
    echo "FAIL: setconf is not idempotent" >&2
    exit 1
fi
echo "idempotent setconf: OK"

echo "== uwg showconf (userspace) =="
"$UWG_BIN" showconf "$IFACE"

echo "== PASS: userspace tools smoke test completed =="
exit 0
