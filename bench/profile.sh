#!/bin/bash
set -u
UWG=/root/umbrawg/tools/target/debug/uwg
WORK=/tmp/uwgbench
DUR=${1:-10}
OUT=${2:-/tmp/prof.data}
pkill -f "iperf3 -s" 2>/dev/null
pkill -f "iperf3 -c" 2>/dev/null
sleep 0.5
ip netns exec uwgb2 iperf3 -s -B 10.0.0.2 -p 5201 >/tmp/srv.log 2>&1 &
SRV=$!
for i in $(seq 1 50); do
    ss -ltnH "sport = :5201" | grep -q 5201 && break
    sleep 0.1
done
ip netns exec uwgb1 iperf3 -c 10.0.0.2 -p 5201 -t $((DUR + 6)) -O 1 >/tmp/cli.log 2>&1 &
CLI=$!
sleep 3
ss -tn | grep -q 10.0.0.2 && echo "flow_up" || echo "flow_missing"
perf record -a -g -F 999 -o "$OUT" -- sleep "$DUR" >/dev/null 2>&1
wait $CLI
kill $SRV 2>/dev/null
tail -3 /tmp/cli.log
