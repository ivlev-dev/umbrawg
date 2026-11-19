#!/bin/bash
set -u
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/bench-lib.sh"
W=/root/umbrawg
T=$W/bench/.t
UWGBIN=$W/tools/target/release/uwg
mkdir -p $T

cleanup() { for n in bcli brtr bsrv; do ip netns del $n 2>/dev/null; done; }
cleanup

K1=$($UWGBIN genkey); P1=$(echo "$K1" | $UWGBIN pubkey)
K2=$($UWGBIN genkey); P2=$(echo "$K2" | $UWGBIN pubkey)
obf_block_from_conf $W/bench/obf-params.conf "$UWGBIN" genkey > $T/obf-lines.txt

mkconf() {
  local priv=$1 listen=$2 pub=$3 ep=$4 out=$5
  { echo "[Interface]"; echo "PrivateKey = $priv"; echo "ListenPort = $listen"
    cat $T/obf-lines.txt
    echo; echo "[Peer]"; echo "PublicKey = $pub"; echo "Endpoint = $ep"
    echo "AllowedIPs = 10.9.0.0/24"; echo "PersistentKeepalive = 5"; } > "$out"
}
mkconf "$K1" 51820 "$P2" 192.168.50.20:51821 $T/c.conf
mkconf "$K2" 51821 "$P1" 192.168.50.10:51820 $T/s.conf

ip netns add bcli; ip netns add brtr; ip netns add bsrv
ip link add vc type veth peer name vc2
ip link add vt type veth peer name vt2
ip link set vc netns bcli; ip link set vc2 netns brtr
ip link set vt netns brtr; ip link set vt2 netns bsrv
ip -n bcli addr add 10.0.0.1/24 dev vc
ip -n brtr addr add 10.0.0.10/24 dev vc2
ip -n brtr addr add 192.168.50.10/24 dev vt
ip -n bsrv addr add 192.168.50.20/24 dev vt2
for ns in bcli brtr bsrv; do ip -n $ns link set lo up; done
ip -n bcli link set vc up; ip -n brtr link set vc2 up; ip -n brtr link set vt up; ip -n bsrv link set vt2 up
ip -n brtr link add uwg0 type umbrawg; ip -n brtr link set uwg0 mtu 1420 up
ip -n bsrv link add uwg0 type umbrawg; ip -n bsrv link set uwg0 mtu 1420 up
ip -n brtr addr add 10.9.0.254/24 dev uwg0
ip -n bsrv addr add 10.9.0.2/24 dev uwg0
ip -n bcli addr add 10.9.0.1/32 dev lo
ip -n bcli route add 10.9.0.0/24 via 10.0.0.10
ip -n brtr route add 10.9.0.1/32 via 10.0.0.1 dev vc2
for ns in bcli brtr bsrv; do ip netns exec $ns sysctl -qw net.ipv4.ip_forward=1; ip netns exec $ns sysctl -qw net.ipv4.conf.all.rp_filter=0; done
ip netns exec brtr $UWGBIN setconf uwg0 $T/c.conf || echo "conf-cli-fail"
ip netns exec bsrv $UWGBIN setconf uwg0 $T/s.conf || echo "conf-srv-fail"

echo "-- ping"
ip netns exec bcli ping -c 2 -W 2 -I 10.9.0.1 10.9.0.2 | tail -2

echo "-- no rps baseline 1 flow"
ip netns exec bcli iperf3 -s -1 -D --pidfile /tmp/x1.pid; sleep 0.5
ip netns exec bsrv iperf3 -s -1 -D --pidfile /tmp/x2.pid; sleep 0.5
taskset -c 3 ip netns exec bcli iperf3 -c 10.9.0.2 -B 10.9.0.1 -t 3 -J > /tmp/r.json 2>/dev/null
python3 -c 'import json; s=json.load(open("/tmp/r.json"))["end"]; print("bps", round(s["sum_received"]["bits_per_second"]/1e6,1))'

echo "-- rps=1 (cpu0) 1 flow"

ip netns exec brtr sh -c 'echo 1 > /sys/class/net/vt/queues/rx-0/rps_cpus; echo 1 > /sys/class/net/vc2/queues/rx-0/rps_cpus'
ip netns exec bsrv sh -c 'echo 1 > /sys/class/net/vt2/queues/rx-0/rps_cpus'
ip netns exec bcli iperf3 -s -1 -D --pidfile /tmp/x1.pid; sleep 0.5
ip netns exec bsrv iperf3 -s -1 -D --pidfile /tmp/x2.pid; sleep 0.5

taskset -c 3 ip netns exec bcli iperf3 -c 10.9.0.2 -B 10.9.0.1 -t 3 -J > /tmp/r2.json 2>/dev/null
python3 -c 'import json; s=json.load(open("/tmp/r2.json"))["end"]; print("bps", round(s["sum_received"]["bits_per_second"]/1e6,1))'
echo "softirqs NET_RX:"; grep 'NET_RX' /proc/softirqs

echo "-- rps=7 (cpu0-2) 3 flows"
ip netns exec brtr sh -c 'echo 7 > /sys/class/net/vt/queues/rx-0/rps_cpus; echo 7 > /sys/class/net/vc2/queues/rx-0/rps_cpus'
ip netns exec bsrv sh -c 'echo 7 > /sys/class/net/vt2/queues/rx-0/rps_cpus'
ip netns exec bcli iperf3 -s -1 -D --pidfile /tmp/x1.pid; sleep 0.5
ip netns exec bsrv iperf3 -s -1 -D --pidfile /tmp/x2.pid; sleep 0.5
taskset -c 3 ip netns exec bcli iperf3 -c 10.9.0.2 -B 10.9.0.1 -t 3 -P 3 -J > /tmp/r3.json 2>/dev/null
python3 -c 'import json; s=json.load(open("/tmp/r3.json"))["end"]; print("bps", round(s["sum_received"]["bits_per_second"]/1e6,1))'
echo "softirqs NET_RX:"; grep 'NET_RX' /proc/softirqs
pkill -f 'iperf3 -s'
cleanup
echo done
