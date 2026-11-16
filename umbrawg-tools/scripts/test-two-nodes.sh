#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: test-two-nodes.sh requires root" >&2
    exit 1
fi

command -v ip >/dev/null 2>&1 || { echo "ERROR: ip not found" >&2; exit 1; }
IFACE="${IFACE:-uwg0}"
UWG_BIN="${UWG_BIN:-/root/umbrawg/tools/target/debug/uwg}"
[ -x "$UWG_BIN" ] || { echo "SKIP: uwg binary not found" >&2; exit 0; }

IPERF="${IPERF:-iperf3}"
if ! command -v "$IPERF" >/dev/null 2>&1; then
    echo "SKIP: iperf3 not installed" >&2
    exit 0
fi

MODULE_DIR="/root/umbrawg/module/src"
if ! lsmod | grep -q '^umbrawg '; then
    make -C "$MODULE_DIR" LLVM=1 >/dev/null
    insmod "$MODULE_DIR/umbrawg.ko"
fi

TMPDIR="$(mktemp -d)"
cleanup() {
    set +e
    for ns in ns1 ns2; do
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link del veth1 2>/dev/null || true
    ip link del veth2 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

ip netns add ns1
ip netns add ns2
ip link add veth1 type veth peer name veth2
ip link set veth1 netns ns1
ip link set veth2 netns ns2
ip netns exec ns1 ip addr add 10.0.0.1/24 dev veth1
ip netns exec ns2 ip addr add 10.0.0.2/24 dev veth2
ip netns exec ns1 ip link set veth1 up
ip netns exec ns2 ip link set veth2 up
ip netns exec ns1 ip link set lo up
ip netns exec ns2 ip link set lo up

run_scenario() {
    local obf="$1"
    echo "===== scenario: obfuscation=$obf ====="

    for ns in ns1 ns2; do
        ip netns exec "$ns" ip link add name "$IFACE" type umbrawg 2>/dev/null || true
        ip netns exec "$ns" ip link set "$IFACE" up
    done
    ip netns exec ns1 ip addr add 10.10.10.1/24 dev "$IFACE"
    ip netns exec ns2 ip addr add 10.10.10.2/24 dev "$IFACE"

    local priv1 pub1 priv2 pub2
    priv1="$("$UWG_BIN" genkey)"
    pub1="$(printf '%s\n' "$priv1" | "$UWG_BIN" pubkey)"
    priv2="$("$UWG_BIN" genkey)"
    pub2="$(printf '%s\n' "$priv2" | "$UWG_BIN" pubkey)"

    local cfg1 cfg2
    cfg1="$TMPDIR/node1_$obf.conf"
    cfg2="$TMPDIR/node2_$obf.conf"

    if [ "$obf" = "1" ]; then
        cp /root/umbrawg/bench/obf-params.conf "$cfg1"
        cp /root/umbrawg/bench/obf-params.conf "$cfg2"
        python3 - "$cfg1" "$priv1" "$pub2" <<PY
import sys
p,priv,peer=sys.argv[1],sys.argv[2],sys.argv[3]
s=open(p).read()
s=s.replace("PLACEHOLDER_REPLACE_WITH_GENERATED_KEY",priv)
s=s.replace("PLACEHOLDER_REPLACE_WITH_PEER_KEY",peer)
s=s.replace("AllowedIPs = 10.9.0.0/24","AllowedIPs = 10.10.10.0/24")
open(p,"w").write(s)
PY
        python3 - "$cfg2" "$priv2" "$pub1" <<PY
import sys
p,priv,peer=sys.argv[1],sys.argv[2],sys.argv[3]
s=open(p).read()
s=s.replace("PLACEHOLDER_REPLACE_WITH_GENERATED_KEY",priv)
s=s.replace("PLACEHOLDER_REPLACE_WITH_PEER_KEY",peer)
s=s.replace("AllowedIPs = 10.9.0.0/24","AllowedIPs = 10.10.10.0/24")
open(p,"w").write(s)
PY
        python3 - "$cfg1" "$cfg2" <<PY
import sys
for p in sys.argv[1:]:
    s=open(p).read()
    s=s.replace("AllowedIPs = 10.9.0.0/24","AllowedIPs = 10.10.10.0/24")
    open(p,"w").write(s)
PY
        # endpoint for peer: node2 needs peer endpoint ns1 underlay? wg peer endpoint is remote
        # Add Endpoint via set after config? config peer section expects endpoint perhaps. Append Endpoint not present.
        # We'll set endpoint via uwg set instead.
    else
        cat >"$cfg1" <<EOF
[Interface]
PrivateKey = $priv1
ListenPort = 51820

[Peer]
PublicKey = $pub2
AllowedIPs = 10.10.10.0/24
Endpoint = 10.0.0.2:51820
PersistentKeepalive = 25
EOF
        cat >"$cfg2" <<EOF
[Interface]
PrivateKey = $priv2
ListenPort = 51820

[Peer]
PublicKey = $pub1
AllowedIPs = 10.10.10.0/24
Endpoint = 10.0.0.1:51820
PersistentKeepalive = 25
EOF
    fi

    # apply baseline config (obf config lacks Endpoint; set it separately)
    ip netns exec ns1 "$UWG_BIN" setconf "$IFACE" "$cfg1"
    ip netns exec ns2 "$UWG_BIN" setconf "$IFACE" "$cfg2"

    if [ "$obf" = "1" ]; then
        ip netns exec ns1 "$UWG_BIN" set "$IFACE" peer "$pub2" endpoint 10.0.0.2:51820 persistent-keepalive 25
        ip netns exec ns2 "$UWG_BIN" set "$IFACE" peer "$pub1" endpoint 10.0.0.1:51820 persistent-keepalive 25
    fi

    ip netns exec ns1 ip link set "$IFACE" up
    ip netns exec ns2 ip link set "$IFACE" up

    echo "-- ping --"
    ip netns exec ns1 ping -c 3 -W 2 10.10.10.2

    echo "-- iperf3 tcp 3s --"
    ip netns exec ns2 "$IPERF" -s -D -p 5201
    sleep 1
    ip netns exec ns1 "$IPERF" -c 10.10.10.2 -p 5201 -t 3
    pkill -f "iperf3 -s" 2>/dev/null || true
    sleep 1

    echo "-- iperf3 udp 3s --"
    ip netns exec ns2 "$IPERF" -s -D -p 5202
    sleep 1
    ip netns exec ns1 "$IPERF" -c 10.10.10.2 -p 5202 -u -t 3 -b 10M
    pkill -f "iperf3 -s" 2>/dev/null || true

    # teardown interfaces for next scenario
    ip netns exec ns1 ip link del "$IFACE" 2>/dev/null || true
    ip netns exec ns2 ip link del "$IFACE" 2>/dev/null || true
    sleep 1
}

run_scenario 0
run_scenario 1

echo "===== PASS: two-node tunnel tests completed ====="
exit 0
