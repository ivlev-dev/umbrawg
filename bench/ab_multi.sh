#!/bin/bash
# Мультипировый A/B: <build-dir> <label> <peers> <proto>
set -u
BIN=${1:?}
LABEL=${2:?}
PEERS=${3:-4}
PROTO=${4:-tcp}
KO=$BIN/src/umbrawg.ko
MODDIR=/lib/modules/$(uname -r)/extra

WANT=$(modinfo -F srcversion "$KO" 2>/dev/null)
cp "$KO" "$MODDIR/umbrawg.ko" || exit 1
rmmod umbrawg 2>/dev/null
modprobe umbrawg || exit 1
GOT=$(cat /sys/module/umbrawg/srcversion 2>/dev/null)
if [ "$WANT" != "$GOT" ]; then echo "SRCVERSION_MISMATCH"; fi

cd /root/umbrawg/bench || exit 1
python3 setup.py --teardown >/dev/null 2>&1
python3 setup.py --peers "$PEERS" --mode plain >/dev/null 2>&1 || { echo "setup failed"; exit 1; }
ip -n uwgb1 link show uwg0 >/dev/null 2>&1 || { echo "device missing"; exit 1; }

python3 iperf.py --proto "$PROTO" --seconds 5 --reps 1 --label "$LABEL-p$PEERS" --out /tmp/multi.json >/dev/null 2>&1
AFTER=$(cat /sys/module/umbrawg/srcversion 2>/dev/null)
DEVS_OK=0
ip -n uwgb1 link show uwg0 >/dev/null 2>&1 && ip -n uwgb2 link show uwg0 >/dev/null 2>&1 && DEVS_OK=1
python3 - "$LABEL" "$PEERS" "$PROTO" "$GOT" "$AFTER" "$DEVS_OK" <<'PY'
import json, sys
label, peers, proto, want, after, devs = sys.argv[1:7]
try:
    d = json.load(open("/tmp/multi.json"))
    r = d["runs"][proto]
    gbps, lost = r["aggregate_gbps"], r.get("udp_lost_percent") or 0.0
except Exception as e:
    gbps, lost = -1.0, -1.0
print(f"{label},p{peers},{proto},{gbps:.4f},{lost:.2f},{want},{after},{devs}")
PY
