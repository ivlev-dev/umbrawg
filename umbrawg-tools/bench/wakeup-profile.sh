#!/bin/bash
set -euo pipefail

usage() {
    cat <<'EOF'
Профиль wakeup: perf record (-F 1500 -g) по всему прогону bench.sh.

Использование:
  wakeup-profile.sh <master|wakeup> <метка> [--help]

Печатает строку Mbit из лога прогона и top-30 символов с долей сэмплов
(queue_work_on, try_to_wake_up и ниже по стеку). Данные: $OUT.data,
лог: $OUT.log, CSV: $OUT.csv.

Переменные окружения:
  MODDIR   каталог src с umbrawg.ko (по умолчанию
           $WORKSPACE_ROOT/module-<вариант>/src, затем
           $WORKSPACE_ROOT/umbrawg-linux-kernel-module/src)
  OUT      префикс выходных файлов (по умолчанию /tmp/prof-<вариант>-<метка>)
  DUR      длительность прогона, секунд (8)
  PROTO    tcp или udp (tcp)
  CONNS    число потоков (1)
  MODE     1c или 3c (1c)
  OBF      0 или 1 (0)
  PERF_HZ  частота сэмплирования (1500)
  IDLE_LOAD_MAX  порог load average (0.9)

Нужен root: netns, insmod, perf.
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi
if [ $# -lt 2 ] || [ -z "${1:-}" ] || [ -z "${2:-}" ]; then
    usage >&2
    exit 2
fi

V=$1
TAG=$2
DUR=${DUR:-8}
PROTO=${PROTO:-tcp}
CONNS=${CONNS:-1}
MODE=${MODE:-1c}
OBF=${OBF:-0}
PERF_HZ=${PERF_HZ:-1500}
IDLE_LOAD_MAX=${IDLE_LOAD_MAX:-0.9}
WAIT_TRIES=${WAIT_TRIES:-120}
WAIT_STEP=${WAIT_STEP:-5}

case "$V" in
    master|wakeup) ;;
    *)
        echo "вариант должен быть master или wakeup: '$V'" >&2
        exit 2
        ;;
esac

BENCH_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$BENCH_DIR/.." && pwd)
WORKSPACE_ROOT=${WORKSPACE_ROOT:-$(cd "$REPO_ROOT/.." && pwd)}
. "$BENCH_DIR/bench-lib.sh"

MODDIR=${MODDIR:-$(first_existing_dir \
    "$WORKSPACE_ROOT/module-$V/src" \
    "$WORKSPACE_ROOT/umbrawg-linux-kernel-module/src")}
OUT=${OUT:-/tmp/prof-$V-$TAG}
DATA=$OUT.data
LOG=$OUT.log
CSV=$OUT.csv

if [ "$(id -u)" -ne 0 ]; then
    echo "нужен root: netns, insmod, perf" >&2
    exit 5
fi
command -v perf >/dev/null 2>&1 || {
    echo "нет perf" >&2
    exit 5
}
if [ ! -f "$BENCH_DIR/bench.sh" ]; then
    echo "нет $BENCH_DIR/bench.sh" >&2
    exit 5
fi
if [ -z "$MODDIR" ] || [ ! -f "$MODDIR/umbrawg.ko" ]; then
    echo "нет $MODDIR/umbrawg.ko (задайте MODDIR)" >&2
    exit 5
fi

wait_idle() {
    local load=0 tries=0
    while [ "$tries" -lt "$WAIT_TRIES" ]; do
        load=$(awk '{print $1}' /proc/loadavg)
        if awk -v l="$load" -v m="$IDLE_LOAD_MAX" \
            'BEGIN { exit !(l < m) }' &&
            ! lsmod | awk '$1 == "umbrawg" { f = 1 } END { exit !f }' &&
            [ -z "$(ip netns list | awk '$1 == "bn0" || $1 == "bn1"')" ] &&
            ! pgrep -x iperf3 >/dev/null; then
            return 0
        fi
        tries=$((tries + 1))
        sleep "$WAIT_STEP"
    done
    echo "WAIT_IDLE_TIMEOUT: стенд занят" >&2
    return 1
}

rmmod umbrawg 2>/dev/null || true
wait_idle || exit 3

perf record -q -a -F "$PERF_HZ" -g -o "$DATA" -- \
    env DURATION="$DUR" REPEATS=1 PROTO_LIST="$PROTO" CONNS_LIST="$CONNS" \
    MODE_LIST="$MODE" OBF_LIST="$OBF" PEERS_LIST=1 LOSS_LIST=0 \
    IMPL_LIST=kernel-umbrawg MODDIR="$MODDIR" \
    RESULT="$CSV" RUN_ID="prof-$V-$TAG" bash "$BENCH_DIR/bench.sh" \
    > "$LOG" 2>&1

grep -E 'Mbit' "$LOG" | head -2
perf report -i "$DATA" --stdio -g none --percent-limit 0.3 2>/dev/null |
    grep -E '^ *[0-9]+\.[0-9]+%' | head -30
