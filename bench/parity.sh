#!/bin/bash
# Захват эталонного прогона: <build-dir> <det|obf> <capture-file>
set -u
BIN=${1:?build dir}
MODE=${2:?mode}
CAP=${3:?capture}
cp "$BIN/src/umbrawg.ko" /lib/modules/$(uname -r)/extra/umbrawg.ko || exit 1
rmmod umbrawg 2>/dev/null
modprobe umbrawg || exit 1
cd /root/umbrawg/bench || exit 1
python3 setup.py --teardown >/dev/null 2>&1
python3 setup.py --peers 1 --mode "$MODE" >/dev/null 2>&1 || { echo SETUP_FAIL; exit 1; }
pkill -f "traffic.py --mode sink" >/dev/null 2>&1
sleep 0.2
ip netns exec uwgb2 python3 traffic.py --mode sink --seconds 10 >/tmp/sink.json 2>&1 &
SINK=$!
sleep 0.4
if [ "$MODE" = "det" ]; then
    ip netns exec uwgb1 ping -c 3 -W 1 10.0.0.2 >/dev/null 2>&1
    sleep 0.3
fi
ip netns exec uwgb2 python3 sniff.py --dev vwgb2 --ports 51820-51830 --out "$CAP" --seconds 5 >/tmp/sniff.log 2>&1 &
SNIFF=$!
sleep 0.6
if [ "$MODE" = "obf" ]; then
    ip netns exec uwgb1 ping -c 3 -W 1 10.0.0.2 >/dev/null 2>&1
    sleep 0.2
fi
ip netns exec uwgb1 python3 traffic.py --mode send --sizes ${TRAFFIC_SIZES:-100,300,1000,1300,1390} --count ${TRAFFIC_COUNT:-100} --interval-ms ${TRAFFIC_INTERVAL:-2} >/tmp/send.json 2>&1
wait $SNIFF 2>/dev/null
kill $SINK >/dev/null 2>&1
cat /tmp/sniff.log
cat /tmp/sink.json
cat /tmp/send.json
