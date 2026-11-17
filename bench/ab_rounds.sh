#!/bin/bash
# Интерливрованные A/B-замеры: <out.csv> <rounds>
set -u
OUT=${1:-/tmp/ab.csv}
ROUNDS=${2:-5}
echo "label,proto,gbps,lost,want,after,devs,rc" > "$OUT"
for r in $(seq 1 "$ROUNDS"); do
    for p in tcp udp; do
        for b in base gso; do
            bash /root/umbrawg/bench/ab.sh "/root/umbrawg/bench/ab/$b" "$b" "$p" 5 >> "$OUT"
        done
    done
    echo "round $r done" >&2
done
