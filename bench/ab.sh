#!/bin/bash
# A/B замер: <build-dir> <label> [tcp|udp] [seconds]
set -u
BIN=${1:?build dir}
LABEL=${2:?label}
PROTO=${3:-tcp}
SECS=${4:-5}
MODE=${5:-plain}
KO=$BIN/src/umbrawg.ko
MODDIR=/lib/modules/$(uname -r)/extra
SAFE='-c safe.directory=*'

if [ ! -f "$KO" ]; then echo "no ko: $KO"; exit 1; fi

WANT=$(modinfo -F srcversion "$KO" 2>/dev/null)

cp "$KO" "$MODDIR/umbrawg.ko" || exit 1
rmmod umbrawg 2>/dev/null
modprobe umbrawg || { echo "modprobe failed"; exit 1; }
GOT=$(cat /sys/module/umbrawg/srcversion 2>/dev/null)
if [ "$WANT" != "$GOT" ]; then echo "SRCVERSION_MISMATCH want=$WANT got=$GOT"; fi

cd /root/umbrawg/bench || exit 1
python3 setup.py --peers 1 --mode "$MODE" >/dev/null 2>&1 || { echo "setup failed"; exit 1; }

ip -n uwgb1 link show uwg0 >/dev/null 2>&1 || { echo "device missing after setup"; exit 1; }

pkill -f "iperf3 -s -B 10.0.0.2" >/dev/null 2>&1
pkill -f "iperf3 -c 10.0.0.2" >/dev/null 2>&1
sleep 0.2

ip netns exec uwgb2 iperf3 -s -B 10.0.0.2 -p 5201 >/dev/null 2>&1 &
SRV=$!
sleep 0.7
if [ "$PROTO" = "udp" ]; then
    ip netns exec uwgb1 iperf3 -c 10.0.0.2 -p 5201 -t "$SECS" -O 1 -u -b 0 -J >/tmp/ab.json 2>/dev/null
else
    ip netns exec uwgb1 iperf3 -c 10.0.0.2 -p 5201 -t "$SECS" -O 1 -J >/tmp/ab.json 2>/dev/null
fi
RC=$?
kill $SRV >/dev/null 2>&1
wait $SRV 2>/dev/null

AFTER=$(cat /sys/module/umbrawg/srcversion 2>/dev/null)
DEVS_OK=0
ip -n uwgb1 link show uwg0 >/dev/null 2>&1 && ip -n uwgb2 link show uwg0 >/dev/null 2>&1 && DEVS_OK=1

python3 - "$LABEL" "$PROTO" "$GOT" "$AFTER" "$DEVS_OK" "$RC" <<'PY'
import json, sys
label, proto, want, after, devs, rc = sys.argv[1:7]
gbps = 0.0
lost = 0.0
try:
    d = json.load(open("/tmp/ab.json"))
    end = d["end"]
    if proto == "udp":
        gbps = end["sum"]["bits_per_second"] / 1e9
        lost = end["sum"].get("lost_percent", 0.0)
    else:
        gbps = end.get("sum_received", end["sum_sent"])["bits_per_second"] / 1e9
except Exception:
    gbps = -1.0
print(f"{label},{proto},{gbps:.4f},{lost:.2f},{want},{after},{devs},{rc}")
PY
