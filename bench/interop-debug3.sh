#!/bin/bash
set -uo pipefail

RUSTDIR=/root/umbrawg/rust
MODDIR=/root/umbrawg/module/src
UWG=/root/umbrawg/tools/target/release/uwg
DAEMON=$RUSTDIR/target/release/umbrawg
OBF=/root/umbrawg/bench/obf-params.conf
NS0=uwgd0
NS1=uwgd1
IF0=uwgt0
IF1=uwgt1
PORT0=51820
PORT1=51821

cleanup() {
    pkill -f "umbrawg --foreground $IF1" 2>/dev/null
    ip netns del "$NS0" 2>/dev/null
    ip netns del "$NS1" 2>/dev/null
    rm -f "/var/run/umbrawg/$IF1.sock"
    rmmod umbrawg 2>/dev/null
}
trap cleanup EXIT
cleanup
mkdir -p /var/run/umbrawg
modprobe udp_tunnel; modprobe ip6_udp_tunnel
insmod "$MODDIR/umbrawg.ko"

ip netns add "$NS0"; ip netns add "$NS1"
ip link add vethd0 type veth peer name vethd1
ip link set vethd0 netns "$NS0"; ip link set vethd1 netns "$NS1"
ip -n "$NS0" addr add 192.168.77.1/24 dev vethd0
ip -n "$NS1" addr add 192.168.77.2/24 dev vethd1
ip -n "$NS0" link set vethd0 up; ip -n "$NS1" link set vethd1 up
ip -n "$NS0" link set lo up; ip -n "$NS1" link set lo up

ip netns exec "$NS0" ip link add "$IF0" type umbrawg
UMBRAWG_THREADS=1 UMBRAWG_LOG_LEVEL=debug ip netns exec "$NS1" "$DAEMON" --foreground "$IF1" >/tmp/dbg-user.log 2>&1 &
sleep 1

ip -n "$NS0" addr add 10.9.0.1/24 dev "$IF0"
ip -n "$NS1" addr add 10.9.0.2/24 dev "$IF1"
ip -n "$NS0" link set "$IF0" mtu 1420 up
ip -n "$NS1" link set "$IF1" mtu 1420 up

K0=$("$UWG" genkey); K1=$("$UWG" genkey)
P0=$(printf '%s' "$K0" | "$UWG" pubkey); P1=$(printf '%s' "$K1" | "$UWG" pubkey)
OBFBLOCK=$(grep -vE '^(PrivateKey|ListenPort|PublicKey|AllowedIPs|\[Peer\]|\[Interface\])' "$OBF" || true)
CONF0=$(mktemp); CONF1=$(mktemp)
printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n%s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.9.0.0/24\nEndpoint = 192.168.77.2:%s\nPersistentKeepalive = 5\n' "$K0" "$PORT0" "$OBFBLOCK" "$P1" "$PORT1" > "$CONF0"
printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n%s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.9.0.0/24\nEndpoint = 192.168.77.1:%s\nPersistentKeepalive = 5\n' "$K1" "$PORT1" "$OBFBLOCK" "$P0" "$PORT0" > "$CONF1"

ip netns exec "$NS0" "$UWG" setconf "$IF0" "$CONF0"
ip netns exec "$NS1" "$UWG" setconf "$IF1" "$CONF1"

ip netns exec "$NS1" tcpdump -i vethd1 -n -c 20 udp > /tmp/dbg-capture.txt 2>/dev/null &
CAP=$!
ip netns exec "$NS0" ping -c 2 -W 1 10.9.0.2 >/tmp/dbg-ping.log 2>&1
sleep 6
kill "$CAP" 2>/dev/null
wait "$CAP" 2>/dev/null

echo "=== capture on vethd1 (ns1)"
head -20 /tmp/dbg-capture.txt
echo "=== ss ns1"
ip netns exec "$NS1" ss -uanm | head -10
echo "=== ss ns0"
ip netns exec "$NS0" ss -uanm | head -10
echo "=== user log"
tail -25 /tmp/dbg-user.log
echo "DBG3_DONE"
