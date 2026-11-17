#!/bin/bash
set -u
W=/root/umbrawg
T=$W/bench/.t
UWGBIN=$W/tools/target/release/uwg
mkdir -p $T
cleanup() { for n in tcli tsrv; do ip netns del $n 2>/dev/null; done; }
cleanup
K1=$($UWGBIN genkey); P1=$(echo "$K1" | $UWGBIN pubkey)
K2=$($UWGBIN genkey); P2=$(echo "$K2" | $UWGBIN pubkey)
if [ ! -f $T/obf-lines.txt ]; then
sed -n '/^\[Interface\]/,/^\[Peer\]/p' $W/bench/obf-params.conf | grep -Ev '^(PrivateKey|ListenPort|\[Interface\]|\[Peer\])' | sed '/^[[:space:]]*$/d' > $T/obf-lines.txt
fi
mkconf() { local priv=$1 listen=$2 pub=$3 ep=$4 out=$5
  { echo "[Interface]"; echo "PrivateKey = $priv"; echo "ListenPort = $listen"; cat $T/obf-lines.txt
    echo; echo "[Peer]"; echo "PublicKey = $pub"; echo "Endpoint = $ep"; echo "AllowedIPs = 10.9.0.0/24"; echo "PersistentKeepalive = 5"; } > "$out"; }
mkconf "$K1" 51820 "$P2" 10.0.0.2:51821 $T/tc.conf
mkconf "$K2" 51821 "$P1" 10.0.0.1:51820 $T/ts.conf

ip netns add tcli; ip netns add tsrv
ip link add vc type veth peer name vs
ip link set vc netns tcli; ip link set vs netns tsrv
ip -n tcli addr add 10.0.0.1/24 dev vc; ip -n tsrv addr add 10.0.0.2/24 dev vs
for ns in tcli tsrv; do
  ip -n $ns link set lo up; ip -n $ns link set vc up 2>/dev/null; ip -n $ns link set vs up 2>/dev/null
  ip -n $ns link add uwg0 type umbrawg; ip -n $ns link set uwg0 mtu 1420 up
  ip netns exec $ns sysctl -qw net.ipv4.conf.all.rp_filter=0
done
ip -n tcli addr add 10.9.0.1/24 dev uwg0; ip -n tsrv addr add 10.9.0.2/24 dev uwg0
ip netns exec tcli $UWGBIN setconf uwg0 $T/tc.conf
ip netns exec tsrv $UWGBIN setconf uwg0 $T/ts.conf
ip netns exec tcli ping -c 2 -W 2 10.9.0.2 | tail -1
echo "== cgroup v2 cpuset"
mkdir -p /sys/fs/cgroup/bench-tunnel 2>/dev/null
echo +cpuset > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
echo 0 > /sys/fs/cgroup/bench-tunnel/cpuset.cpus 2>&1 && echo cpuset-set-ok
cat /sys/fs/cgroup/bench-tunnel/cpuset.cpus.effective 2>&1

echo "== traffic + perf record on cpu0 (no rps)"
ip netns exec tsrv iperf3 -s -1 -D --pidfile /tmp/ts.pid; sleep 0.5
ip netns exec tcli iperf3 -c 10.9.0.2 -b 500M -t 8 >/dev/null 2>&1 &
sleep 1
perf record -g -C 0 -o /tmp/perf.data -- sleep 4 >/dev/null 2>&1; echo "perf record rc=$?"
perf report -i /tmp/perf.data --stdio --no-children -g none --sort symbol 2>/dev/null | grep -E '^[[:space:]]+[0-9]' | head -15
echo "== perf stat cpu0"
perf stat -C 0 -e cycles,instructions,branches,branch-misses,cache-misses -- sleep 3 2>&1 | grep -E 'cycles|instructions|branches|cache-misses|seconds'
wait
pkill -f 'iperf3 -s'
echo "== bpftrace"
timeout 6 bpftrace -e 'kprobe:udp_sendmsg { @sends[comm, cpu] = count(); } kprobe:udp_recvmsg { @recvs[comm, cpu] = count(); } interval:s:3 { exit(); }' 2>&1 | head -20
cleanup
echo done
