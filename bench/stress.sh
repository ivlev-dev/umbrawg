#!/bin/bash
# Стресс: циклы пересоздания туннеля + трафик. Проверяет dmesg на KFENCE/lockdep.
set -u
NL=${1:-6}
MODE=${2:-obf}
cd /root/umbrawg/bench || exit 1
DMESG_BEFORE=$(dmesg | wc -l)
for i in $(seq 1 "$NL"); do
    python3 setup.py --teardown >/dev/null 2>&1
    python3 setup.py --peers 3 --mode "$MODE" >/dev/null 2>&1 || { echo "setup failed $i"; exit 1; }
    ip netns exec uwgb1 ping -c 200 -f -W 1 10.0.0.2 >/dev/null 2>&1
    pkill -f "iperf3 -s" >/dev/null 2>&1
    sleep 0.2
    ip netns exec uwgb2 iperf3 -s -B 10.0.0.2 -p 5201 >/dev/null 2>&1 &
    SRV=$!
    sleep 0.6
    ip netns exec uwgb1 iperf3 -c 10.0.0.2 -p 5201 -t 2 -O 0 >/dev/null 2>&1
    ip netns exec uwgb1 iperf3 -c 10.0.0.2 -p 5201 -t 2 -u -b 0 >/dev/null 2>&1
    kill $SRV >/dev/null 2>&1
    wait $SRV 2>/dev/null
    echo "iter $i ok" >&2
done
dmesg | tail -n +$((DMESG_BEFORE + 1)) | grep -cE "KFENCE|BUG:|WARNING:|refcount|Call Trace" || true
dmesg | tail -n +$((DMESG_BEFORE + 1)) | grep -E "KFENCE|BUG:|WARNING:|refcount" | head -5
