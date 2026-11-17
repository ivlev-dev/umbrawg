#!/bin/bash
set -u
pkill -f "iperf3 -s" >/dev/null 2>&1
pkill -f "iperf3 -c" >/dev/null 2>&1
sleep 0.3
ip netns exec uwgb2 iperf3 -s -B 10.0.0.2 -p 5201 >/dev/null 2>&1 &
SRV=$!
sleep 1
ip netns exec uwgb1 iperf3 -c 10.0.0.2 -p 5201 -t 10 -O 2 >/tmp/cli.txt 2>&1 &
CLI=$!
sleep 2
timeout 30 bpftrace -e 'kprobe:__udp_gso_segment { @gso_segments = count(); }
kprobe:udp_tunnel_xmit_skb { @tunnel_xmit = count(); }
kprobe:__alloc_skb { @alloc_skb = count(); }
kprobe:skb_gso_segment { @skb_gso_segment = count(); }
interval:s:6 { exit(); }' 2>/dev/null
wait $CLI
kill $SRV >/dev/null 2>&1
grep -E "sender|receiver" /tmp/cli.txt | tail -2
