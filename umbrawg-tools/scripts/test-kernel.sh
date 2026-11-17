#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: test-kernel.sh requires root" >&2
    exit 1
fi

IFACE="${IFACE:-uwg0}"
TOOLS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE_ROOT="${WORKSPACE_ROOT:-$(cd "$TOOLS_DIR/.." && pwd)}"
BENCH_DIR="${BENCH_DIR:-$TOOLS_DIR/bench}"
. "$BENCH_DIR/bench-lib.sh"
MODULE_DIR="${MODULE_DIR:-${MODDIR:-$(first_existing_dir "$WORKSPACE_ROOT/umbrawg-linux-kernel-module/src" "$WORKSPACE_ROOT/module/src")}}"
BENCH_CONF="${BENCH_CONF:-$BENCH_DIR/obf-params.conf}"
UWG_BIN="${UWG_BIN:-$TOOLS_DIR/target/debug/uwg}"

if [ ! -x "$UWG_BIN" ]; then
    for candidate in uwg "$TOOLS_DIR/target/release/uwg"; do
        if command -v "$candidate" >/dev/null 2>&1; then
            UWG_BIN="$(command -v "$candidate")"
            break
        fi
    done
fi
if [ ! -x "$UWG_BIN" ]; then
    echo "building uwg..."
    (cd "$TOOLS_DIR" && cargo build -p uwg >/dev/null)
    UWG_BIN="$TOOLS_DIR/target/debug/uwg"
fi
[ -x "$UWG_BIN" ] || { echo "ERROR: uwg binary not found" >&2; exit 1; }
[ -n "$MODULE_DIR" ] || { echo "ERROR: module dir not found, задай MODULE_DIR" >&2; exit 1; }
[ -f "$BENCH_CONF" ] || { echo "ERROR: bench config not found: $BENCH_CONF" >&2; exit 1; }

TMPDIR="$(mktemp -d)"
cleanup() {
    set +e
    ip link del "$IFACE" 2>/dev/null || true
    if lsmod 2>/dev/null | grep -q '^umbrawg '; then
        rmmod umbrawg 2>/dev/null || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "== build module =="
make -C "$MODULE_DIR" LLVM=1

echo "== load module =="
if ! lsmod | grep -q '^umbrawg '; then
    insmod "$MODULE_DIR/umbrawg.ko"
fi

echo "== create interface =="
ip link add name "$IFACE" type umbrawg
ip link set "$IFACE" up

PRIV="$("$UWG_BIN" genkey)"
PEER_PRIV="$("$UWG_BIN" genkey)"
PEER_PUB="$(printf '%s\n' "$PEER_PRIV" | "$UWG_BIN" pubkey)"

CFG="$TMPDIR/test.conf"
cp "$BENCH_CONF" "$CFG"
sed -i "s/PLACEHOLDER_REPLACE_WITH_GENERATED_KEY/$PRIV/" "$CFG"
sed -i "s/PLACEHOLDER_REPLACE_WITH_PEER_KEY/$PEER_PUB/" "$CFG"
printf '%s\n' "$(grep '^HeaderProtectionKey' "$BENCH_CONF" | cut -d= -f2- | tr -d ' ')" >"$TMPDIR/hpk.key"

echo "== uwg setconf (all 3.1 fields) =="
"$UWG_BIN" setconf "$IFACE" "$CFG"

echo "== uwg show =="
"$UWG_BIN" show "$IFACE"

echo "== uwg showconf =="
"$UWG_BIN" showconf "$IFACE"

echo "== idempotent setconf check =="
before="$("$UWG_BIN" showconf "$IFACE")"
"$UWG_BIN" setconf "$IFACE" "$CFG"
after="$("$UWG_BIN" showconf "$IFACE")"
if [ "$before" != "$after" ]; then
    echo "FAIL: setconf is not idempotent" >&2
    exit 1
fi
echo "idempotent setconf: OK"

echo "== uwg set (all 3.1 fields) =="
"$UWG_BIN" set "$IFACE" \
    listen-port 51820 \
    jc 6 jmin 292 jmax 1152 \
    s1 34 s2 97 s3 31 s4 28 \
    h1 712026294-712074283 \
    h2 1504260570-1504277407 \
    h3 2938347170-2938351405 \
    h4 3916942126-3916960536 \
    i1 "<b 0xc200000001087972af009f7ce47d04559703f31e174691922b896cb39e5ccdb74b8f6c46168d47652d74a98a2861c7349b5244b64eb876><rc 38><r 1000><r 161><t>" \
    i2 "<b 0xe300000001127362d0c517f5aae98388afaf2809110ccc5610ed5923abbcbd29ac5c31816261d0e7ae44bb7fc33941><rc 40><r 1000><r 163><t>" \
    i3 "<b 0xc30000000111bf75ad99b7b31b0d887c05054897ecd7d001911a53c4c9ab0067c318d6d5bf6519134da966559268219aca1fba4644b219ba2c84><rc 41><r 1000><r 153><t>" \
    i4 "<b 0xe100000001093adb1b6b0cde0531700ea127f7f956bc499a0ab59bd6b0dc44c43085><rc 38><r 1000><r 176><t>" \
    i5 "<b 0xe2000000010973760ff2b80f2c78420a91d8a812337b91c48c2844d7b63a2d><rc 40><r 1000><r 192><t>" \
    header-protection-key "$TMPDIR/hpk.key" \
    content-padding-addition "51-197" \
    rekey-after-time "104-149" \
    rekey-timeout "5-8" \
    reject-after-time "184-199" \
    keepalive-timeout "9-12" \
    max-handshake-attempts "18-23" \
    random-trailers on \
    disable-cookies off

echo "== verify selected fields =="
"$UWG_BIN" show "$IFACE" jc
"$UWG_BIN" show "$IFACE" random-trailers

echo "== PASS: kernel tools smoke test completed =="
exit 0
