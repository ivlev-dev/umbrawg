#!/bin/bash
set -euo pipefail

BENCH_DIR=${BENCH_DIR:-$(cd "$(dirname "$0")" && pwd)}
REPO_ROOT=$(cd "$BENCH_DIR/.." && pwd)
WORKSPACE_ROOT=${WORKSPACE_ROOT:-$(cd "$REPO_ROOT/.." && pwd)}
. "$BENCH_DIR/bench-lib.sh"

RUSTDIR=${RUSTDIR:-$(first_existing_dir "$WORKSPACE_ROOT/umbrawg-rs" "$WORKSPACE_ROOT/rust")}
UWG=${UWG:-$(first_existing_file "$REPO_ROOT/target/release/uwg" "$WORKSPACE_ROOT/umbrawg-tools/target/release/uwg" "$WORKSPACE_ROOT/tools/target/release/uwg")}
DAEMON=${DAEMON:-$(first_existing_file "$RUSTDIR/target/release/umbrawg" "$RUSTDIR/umbrawg")}
OBF=${OBF:-$BENCH_DIR/obf-params.conf}
NS0=uwgu0
NS1=uwgu1
IF0=uwgt0
IF1=uwgt1
V0=vethu0
V1=vethu1
PORT0=51820
PORT1=51821
OBF_ON=${OBF_ON:-1}
THREADS=${THREADS:-4}

cleanup() {
    set +e
    pkill -f "umbrawg --foreground $IF0" 2>/dev/null
    pkill -f "umbrawg --foreground $IF1" 2>/dev/null
    ip netns del "$NS0" 2>/dev/null
    ip netns del "$NS1" 2>/dev/null
    rm -f "/var/run/umbrawg/$IF0.sock" "/var/run/umbrawg/$IF1.sock"
}
trap cleanup EXIT

cleanup
mkdir -p /var/run/umbrawg
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

UMBRAWG_THREADS=$THREADS ip netns exec "$NS0" "$DAEMON" --foreground "$IF0" >/tmp/umbrawg-$IF0.log 2>&1 &
UMBRAWG_THREADS=$THREADS ip netns exec "$NS1" "$DAEMON" --foreground "$IF1" >/tmp/umbrawg-$IF1.log 2>&1 &

for _ in $(seq 1 50); do
    [ -S "/var/run/umbrawg/$IF0.sock" ] && [ -S "/var/run/umbrawg/$IF1.sock" ] && break
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

"$UWG" setconf "$IF0" "$CONF0"
"$UWG" setconf "$IF1" "$CONF1"

echo "=== show"
"$UWG" show "$IF0" | sed -n '1,14p'

echo "=== ping"
if ! ip netns exec "$NS0" ping -c 3 -W 2 10.9.0.2; then
    echo "PING_FAILED"
    echo "--- log $IF0"; tail -20 "/tmp/umbrawg-$IF0.log"
    echo "--- log $IF1"; tail -20 "/tmp/umbrawg-$IF1.log"
    exit 1
fi

echo "=== tcp"
ip netns exec "$NS1" iperf3 -s -1 -D --logfile /tmp/iperf-usr-srv.log
sleep 1
ip netns exec "$NS0" iperf3 -c 10.9.0.2 -t 3 -P 1 -J > /tmp/iperf-usr-tcp.json
python3 - <<'PY'
import json
d = json.load(open('/tmp/iperf-usr-tcp.json'))
print("TCP Mbit/s", round(d['end']['sum_received']['bits_per_second'] / 1e6, 1))
PY

echo "=== udp"
ip netns exec "$NS1" iperf3 -s -1 -D --logfile /tmp/iperf-usr-srv-udp.log
sleep 1
ip netns exec "$NS0" iperf3 -c 10.9.0.2 -t 3 -u -b 0 -l 1340 -J > /tmp/iperf-usr-udp.json
python3 - <<'PY'
import json
d = json.load(open('/tmp/iperf-usr-udp.json'))
s = d['end']['sum']
print("UDP Mbit/s", round(s['bits_per_second'] / 1e6, 1), "lost", s.get('lost_percent'))
PY
echo "VERIFY_USERS_OK"
