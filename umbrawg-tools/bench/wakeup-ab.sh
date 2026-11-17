#!/bin/bash
set -euo pipefail

usage() {
    cat <<'EOF'
A/B коалесинга пробуждений: чередование двух сборок модуля (master/wakeup).

Использование:
  wakeup-ab.sh [--master DIR] [--wakeup DIR] [--rounds N] [--outdir DIR]
               [--tag NAME] [--cooldown SEC] [--help]

Каждый раунд запускает bench.sh для каждой сборки; порядок вариантов
меняется каждый раунд, чтобы дрейф машины не смещал результат. Результаты:
  <outdir>/<tag>-master.csv, <outdir>/<tag>-wakeup.csv (+ .diag/.agg.csv/.md)

Переменные окружения:
  MASTER, WAKEUP       каталоги src с umbrawg.ko (по умолчанию
                       $WORKSPACE_ROOT/module-master/src и
                       $WORKSPACE_ROOT/module-wakeup/src)
  ROUNDS               число раундов, по умолчанию 5
  OUTDIR               каталог результатов, по умолчанию $BENCH_DIR/results
  TAG                  префикс файлов, по умолчанию wakeup-ab
  COOLDOWN             пауза между раундами, секунд (20)
  IDLE_LOAD_MAX        порог load average перед прогоном (0.9)
  DURATION, REPEATS, CONNS_LIST, OBF_LIST, MODE_LIST, PROTO_LIST,
  PEERS_LIST, LOSS_LIST, UDP_RATE_LIST, IMPL_LIST, UNDERLAY_MTU, TUN_MTU
                       передаются в bench.sh (значения по умолчанию ниже)

Нужен root: netns, insmod, perf-free запуск bench.sh.
EOF
}

ARG_MASTER=""
ARG_WAKEUP=""
ARG_ROUNDS=""
ARG_OUTDIR=""
ARG_TAG=""
ARG_COOLDOWN=""

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --master)
            ARG_MASTER=${2:?--master требует каталог}
            shift 2
            ;;
        --wakeup)
            ARG_WAKEUP=${2:?--wakeup требует каталог}
            shift 2
            ;;
        --rounds)
            ARG_ROUNDS=${2:?--rounds требует число}
            shift 2
            ;;
        --outdir)
            ARG_OUTDIR=${2:?--outdir требует каталог}
            shift 2
            ;;
        --tag)
            ARG_TAG=${2:?--tag требует имя}
            shift 2
            ;;
        --cooldown)
            ARG_COOLDOWN=${2:?--cooldown требует секунды}
            shift 2
            ;;
        *)
            echo "неизвестный аргумент: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

BENCH_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$BENCH_DIR/.." && pwd)
WORKSPACE_ROOT=${WORKSPACE_ROOT:-$(cd "$REPO_ROOT/.." && pwd)}
. "$BENCH_DIR/bench-lib.sh"

ROUNDS=${ARG_ROUNDS:-${ROUNDS:-5}}
OUTDIR=${ARG_OUTDIR:-${OUTDIR:-$BENCH_DIR/results}}
TAG=${ARG_TAG:-${TAG:-wakeup-ab}}
COOLDOWN=${ARG_COOLDOWN:-${COOLDOWN:-20}}
IDLE_LOAD_MAX=${IDLE_LOAD_MAX:-0.9}
WAIT_TRIES=${WAIT_TRIES:-90}
WAIT_STEP=${WAIT_STEP:-5}
MASTER=${ARG_MASTER:-${MASTER:-${MASTER_DIR:-$(first_existing_dir \
    "$WORKSPACE_ROOT/module-master/src" \
    "$WORKSPACE_ROOT/umbrawg-linux-kernel-module/src")}}}
WAKEUP=${ARG_WAKEUP:-${WAKEUP:-${WAKEUP_DIR:-$(first_existing_dir \
    "$WORKSPACE_ROOT/module-wakeup/src" \
    "$WORKSPACE_ROOT/umbrawg-linux-kernel-module/src")}}}

export DURATION=${DURATION:-8}
export REPEATS=${REPEATS:-1}
export CONNS_LIST=${CONNS_LIST:-"1 10"}
export OBF_LIST=${OBF_LIST:-"0 1"}
export MODE_LIST=${MODE_LIST:-"1c 3c"}
export PROTO_LIST=${PROTO_LIST:-"tcp udp"}
export PEERS_LIST=${PEERS_LIST:-1}
export LOSS_LIST=${LOSS_LIST:-0}
export UDP_RATE_LIST=${UDP_RATE_LIST:-1G}
export IMPL_LIST=${IMPL_LIST:-kernel-umbrawg}
export UNDERLAY_MTU=${UNDERLAY_MTU:-9000}
export TUN_MTU=${TUN_MTU:-1420}

if [ "$(id -u)" -ne 0 ]; then
    echo "нужен root: netns, insmod, iperf3" >&2
    exit 5
fi
if [ ! -f "$BENCH_DIR/bench.sh" ]; then
    echo "нет $BENCH_DIR/bench.sh" >&2
    exit 5
fi
for dir in "$MASTER" "$WAKEUP"; do
    if [ -z "$dir" ] || [ ! -d "$dir" ]; then
        echo "нет каталога сборки: '${dir}' (задайте MASTER/WAKEUP)" >&2
        exit 5
    fi
done

mkdir -p "$OUTDIR"
rm -f "$OUTDIR/$TAG-master.csv" "$OUTDIR/$TAG-wakeup.csv"

wait_idle() {
    local load=0 tries=0
    while [ "$tries" -lt "$WAIT_TRIES" ]; do
        load=$(awk '{print $1}' /proc/loadavg)
        if awk -v l="$load" -v m="$IDLE_LOAD_MAX" \
            'BEGIN { exit !(l < m) }'; then
            return 0
        fi
        tries=$((tries + 1))
        sleep "$WAIT_STEP"
    done
    echo "WAIT_LOAD_TIMEOUT: load $load >= $IDLE_LOAD_MAX" >&2
    return 0
}

for r in $(seq 1 "$ROUNDS"); do
    if [ $((r % 2)) -eq 1 ]; then
        order="master wakeup"
    else
        order="wakeup master"
    fi
    for v in $order; do
        case "$v" in
            master) dir=$MASTER ;;
            wakeup) dir=$WAKEUP ;;
        esac
        echo "=== round $r variant $v $(date +%H:%M:%S) ===" >&2
        wait_idle
        (
            cd "$BENCH_DIR" || exit 1
            MODDIR=$dir RESULT="$OUTDIR/$TAG-$v.csv" RUN_ID="$v-r$r" \
                bash bench.sh
        ) >&2 || echo "RUN_FAILED round=$r variant=$v" >&2
    done
    sleep "$COOLDOWN"
done
echo "DONE $(date +%H:%M:%S)" >&2
