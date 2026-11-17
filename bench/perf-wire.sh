#!/bin/bash
set -uo pipefail
KO=/root/umbrawg/module-wire/src/umbrawg.ko
UWG=/root/umbrawg/tools/target/release/uwg
NS0=wkg0; NS1=wkg1; WQ=/sys/devices/virtual/workqueue/cpumask
OUT=/root/umbrawg/bench/tmp/perf-wire
OLDWQ=$(cat $WQ)

cleanup() {
    set +e
    [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null
    [ -n "${CLI:-}" ] && kill "$CLI" 2>/dev/null
    ip netns del $NS0 2>/dev/null; ip netns del $NS1 2>/dev/null
    rmmod umbrawg 2>/dev/null
    echo "$OLDWQ" > $WQ
}
trap cleanup EXIT

modprobe udp_tunnel; modprobe ip6_udp_tunnel
insmod "$KO"
ip netns add $NS0; ip netns add $NS1
ip link add wkgv0 type veth peer name wkgv1 numtxqueues 6 numrxqueues 6
ip link set wkgv0 netns $NS0; ip link set wkgv1 netns $NS1
ip -n $NS0 addr add 192.168.77.1/24 dev wkgv0; ip -n $NS1 addr add 192.168.77.2/24 dev wkgv1
ip -n $NS0 link set wkgv0 mtu 9000 up; ip -n $NS1 link set wkgv1 mtu 9000 up
ip -n $NS0 link set lo up; ip -n $NS1 link set lo up
ip netns exec $NS0 ip link add uwg0 type umbrawg
ip netns exec $NS1 ip link add uwg1 type umbrawg
ip -n $NS0 addr add 10.9.0.1/24 dev uwg0; ip -n $NS1 addr add 10.9.0.2/24 dev uwg1
ip -n $NS0 link set uwg0 mtu 1420 up; ip -n $NS1 link set uwg1 mtu 1420 up
K0=$($UWG genkey); P0=$(printf %s "$K0"|$UWG pubkey)
K1=$($UWG genkey); P1=$(printf %s "$K1"|$UWG pubkey)
OBF=$(cat /root/umbrawg/bench/obf-compat.conf)
printf "[Interface]\nPrivateKey = $K0\nListenPort = 53920\n$OBF\n\n[Peer]\nPublicKey = $P1\nAllowedIPs = 10.9.0.0/24\nEndpoint = 192.168.77.2:53921\nPersistentKeepalive = 5\n" > /tmp/pw0
printf "[Interface]\nPrivateKey = $K1\nListenPort = 53921\n$OBF\n\n[Peer]\nPublicKey = $P0\nAllowedIPs = 10.9.0.0/24\nEndpoint = 192.168.77.1:53920\nPersistentKeepalive = 5\n" > /tmp/pw1
ip netns exec $NS0 $UWG setconf uwg0 /tmp/pw0
ip netns exec $NS1 $UWG setconf uwg1 /tmp/pw1
for _ in $(seq 1 30); do ip netns exec $NS0 ping -c1 -W1 10.9.0.2 >/dev/null 2>&1 && break; sleep 0.3; done
echo 1 > $WQ
ip netns exec $NS1 taskset -c 3 iperf3 -s -1 -p 5201 -D --pidfile /tmp/pw-srv.pid --logfile /tmp/pw-srv.log
SRV=$(cat /tmp/pw-srv.pid)
ip netns exec $NS0 taskset -c 3 iperf3 -c 10.9.0.2 -p 5201 -t 16 -l 1420 >/tmp/pw-cli.log 2>&1 &
CLI=$!
sleep 3
perf record -a -g -F 999 -o "$OUT.data" -- sleep 8 >/dev/null 2>&1
wait $CLI 2>/dev/null
kill $SRV 2>/dev/null
perf report -i "$OUT.data" --stdio --no-children -g none --sort symbol 2>/dev/null > "$OUT.self"
perf report -i "$OUT.data" --stdio --children -g none --sort symbol 2>/dev/null > "$OUT.incl"
tail -3 /tmp/pw-cli.log
echo "=== SELF"
sed -n '/^$/,$p' "$OUT.self" | grep -E "^ +[0-9]" | head -25
echo "=== INCLUSIVE"
sed -n '/^$/,$p' "$OUT.incl" | grep -E "^ +[0-9]" | head -25
echo "=== HOT KEYWORDS"
grep -E "wake|queue_work|lock|spin|mutex|skb_|copy|encrypt|decrypt|chacha|poly|napi|gro|gso" "$OUT.self" | head -20
