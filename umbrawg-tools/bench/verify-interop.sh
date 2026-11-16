#!/bin/bash
set -euo pipefail

RUSTDIR=${RUSTDIR:-/root/umbrawg/rust}
MODDIR=${MODDIR:-/root/umbrawg/module/src}
UWG=${UWG:-/root/umbrawg/tools/target/release/uwg}
DAEMON=${DAEMON:-$RUSTDIR/target/release/umbrawg}
OBF=${OBF:-/root/umbrawg/bench/obf-params.conf}
NS0=uwgi0
NS1=uwgi1
IF0=uwgt0
IF1=uwgt1
V0=vethi0
V1=vethi1
PORT0=51820
PORT1=51821
OBF_ON=${OBF_ON:-1}
MODE=${MODE:-kernel-first}

uwg_ns() {
    local ns=$1
    shift
    ip netns exec "$ns" "$UWG" "$@"
}

cleanup() {
    set +e
    pkill -f "umbrawg --foreground $IF0" 2>/dev/null
    pkill -f "umbrawg --foreground $IF1" 2>/dev/null
    ip netns del "$NS0" 2>/dev/null
    ip netns del "$NS1" 2>/dev/null
    rm -f "/var/run/umbrawg/$IF0.sock" "/var/run/umbrawg/$IF1.sock"
    rmmod umbrawg 2>/dev/null
}
trap cleanup EXIT

cleanup
mkdir -p /var/run/umbrawg
modprobe udp_tunnel
modprobe ip6_udp_tunnel
insmod "$MODDIR/umbrawg.ko"

ip netns add "$NS0"
ip netns add "$NS1"
ip link add "$V0" type veth peer name "$V1"
ip link set "$V0" netns "$NS0"
ip link set "$V1" netns "$NS1"
ip -n "$NS0" addr add 192.168.77.1/24 dev "$V0"
ip -n "$NS1" addr add 192.168.77.2/24 dev "$V1"
ip -n "$NS0" link set "$V0" up
ip -n "$NS1" link set "$V1" up
ip -n "$NS0" link set lo up
ip -n "$NS1" link set lo up

if [ "$MODE" = "kernel-first" ]; then
    KERNEL_NS=$NS0
    USER_NS=$NS1
    KERNEL_IF=$IF0
    USER_IF=$IF1
else
    KERNEL_NS=$NS1
    USER_NS=$NS0
    KERNEL_IF=$IF1
    USER_IF=$IF0
fi

ip netns exec "$KERNEL_NS" ip link add "$KERNEL_IF" type umbrawg
UMBRAWG_THREADS=${THREADS:-4} ip netns exec "$USER_NS" "$DAEMON" --foreground "$USER_IF" >"/tmp/umbrawg-$USER_IF.log" 2>&1 &
for _ in $(seq 1 50); do
    [ -S "/var/run/umbrawg/$USER_IF.sock" ] && break
    sleep 0.1
done

ip -n "$NS0" addr add 10.9.0.1/24 dev "$IF0"
ip -n "$NS1" addr add 10.9.0.2/24 dev "$IF1"
ip -n "$NS0" link set "$IF0" mtu 1420 up
ip -n "$NS1" link set "$IF1" mtu 1420 up

K0=$("$UWG" genkey)
K1=$("$UWG" genkey)
P0=$(printf '%s' "$K0" | "$UWG" pubkey)
P1=$(printf '%s' "$K1" | "$UWG" pubkey)

OBFBLOCK=""
if [ "$OBF_ON" = "1" ]; then
    OBFBLOCK=$(grep -vE '^(PrivateKey|ListenPort|PublicKey|AllowedIPs|\[Peer\]|\[Interface\])' "$OBF" || true)
fi

CONF0=$(mktemp)
CONF1=$(mktemp)
{
    echo "[Interface]"
    echo "PrivateKey = $K0"
    echo "ListenPort = $PORT0"
    [ -n "$OBFBLOCK" ] && echo "$OBFBLOCK"
    echo
    echo "[Peer]"
    echo "PublicKey = $P1"
    echo "AllowedIPs = 10.9.0.0/24"
    echo "Endpoint = 192.168.77.2:$PORT1"
    echo "PersistentKeepalive = 5"
} > "$CONF0"
{
    echo "[Interface]"
    echo "PrivateKey = $K1"
    echo "ListenPort = $PORT1"
    [ -n "$OBFBLOCK" ] && echo "$OBFBLOCK"
    echo
    echo "[Peer]"
    echo "PublicKey = $P0"
    echo "AllowedIPs = 10.9.0.0/24"
    echo "Endpoint = 192.168.77.1:$PORT0"
    echo "PersistentKeepalive = 5"
} > "$CONF1"

uwg_ns "$NS0" setconf "$IF0" "$CONF0"
uwg_ns "$NS1" setconf "$IF1" "$CONF1"

echo "=== mode $MODE, obf=$OBF_ON, kernel=$KERNEL_NS/$KERNEL_IF, userspace=$USER_NS/$USER_IF"
echo "=== ports"
uwg_ns "$NS0" show "$IF0" | grep -E "listening port|endpoint" || true
uwg_ns "$NS1" show "$IF1" | grep -E "listening port|endpoint" || true

echo "=== ping"
if ! ip netns exec "$NS0" ping -c 12 -i 1 -W 2 10.9.0.2; then
    echo "PING_FAILED"
    echo "--- kernel show"
    uwg_ns "$KERNEL_NS" show "$KERNEL_IF" || true
    echo "--- userspace log"
    tail -30 "/tmp/umbrawg-$USER_IF.log"
    exit 1
fi

echo "=== tcp"
ip netns exec "$NS1" iperf3 -s -1 -D --logfile /tmp/iperf-int-srv.log
sleep 1
ip netns exec "$NS0" iperf3 -c 10.9.0.2 -t 3 -P 1 -J > /tmp/iperf-int-tcp.json
python3 - <<'PY'
import json
d = json.load(open('/tmp/iperf-int-tcp.json'))
print("TCP Mbit/s", round(d['end']['sum_received']['bits_per_second'] / 1e6, 1))
PY

echo "=== udp"
ip netns exec "$NS1" iperf3 -s -1 -D --logfile /tmp/iperf-int-srv-udp.log
sleep 1
ip netns exec "$NS0" iperf3 -c 10.9.0.2 -t 3 -u -b 500M -l 1340 -J > /tmp/iperf-int-udp.json
python3 - <<'PY'
import json
d = json.load(open('/tmp/iperf-int-udp.json'))
s = d['end']['sum']
print("UDP Mbit/s", round(s['bits_per_second'] / 1e6, 1), "lost", s.get('lost_percent'))
PY

echo "INTEROP_OK"
