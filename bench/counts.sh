#!/bin/bash
# Счётчики вызовов на фиксированном трафике: <build-dir>
set -u
BIN=${1:?build dir}
cp "$BIN/src/umbrawg.ko" /lib/modules/$(uname -r)/extra/umbrawg.ko || exit 1
rmmod umbrawg 2>/dev/null
modprobe umbrawg || exit 1
cd /root/umbrawg/bench || exit 1
python3 setup.py --teardown >/dev/null 2>&1
python3 setup.py --peers 1 --mode plain >/dev/null 2>&1 || exit 1
pkill -f "traffic.py --mode sink" >/dev/null 2>&1
sleep 0.2
ip netns exec uwgb2 python3 traffic.py --mode sink --seconds 9 >/tmp/sink.json 2>&1 &
SINK=$!
sleep 0.5
ip netns exec uwgb1 ping -c 2 -W 1 10.0.0.2 >/dev/null 2>&1
sleep 0.5
timeout 30 bpftrace -e 'kprobe:udp_tunnel_xmit_skb { @tunnel_xmit = count(); }
kprobe:__udp_gso_segment { @gso_seg = count(); }
kprobe:__alloc_skb { @alloc = count(); }
interval:s:7 { exit(); }' >/tmp/bpf.out 2>&1 &
BPF=$!
sleep 1
ip netns exec uwgb1 python3 traffic.py --mode send --sizes 1400 --count 2000 --interval-ms 0 >/tmp/send.json 2>&1
sleep 1.5
wait $BPF 2>/dev/null
kill $SINK >/dev/null 2>&1
cat /tmp/send.json
cat /tmp/bpf.out
