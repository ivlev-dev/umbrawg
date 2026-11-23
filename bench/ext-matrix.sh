#!/bin/bash
set -uo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
WIRE=${WIRE:-$HERE/wire-ext.sh}

IMPL_LIST=${IMPL_LIST:-rust kernel}
FEC_LIST=${FEC_LIST:-off 2:1 8:2 adaptive}
LOSS_LIST=${LOSS_LIST:-0 2}
DIR_LIST=${DIR_LIST:-k0}

DUR=${DUR:-3}
UMTU=${UMTU:-${UNDERLAY_MTU:-9000}}
TUNMTU=${TUNMTU:-${TUN_MTU:-1420}}
NETEM_DELAY=${NETEM_DELAY:-0}
NETEM_RATE=${NETEM_RATE:-}
NETEM_BOTH=${NETEM_BOTH:-1}
SKIP_PING=${SKIP_PING:-0}
KEEP=${KEEP:-0}
PLAN_ONLY=${PLAN_ONLY:-0}
FAILFAST=${FAILFAST:-0}
TAG=${TAG:-ext}
RUN_ID=${RUN_ID:-$(date +%Y%m%d-%H%M%S)}
OUT=${OUT:-$HERE/tmp/ext-matrix-$RUN_ID.csv}
LOG_DIR=${LOG_DIR:-$HERE/tmp/ext-matrix-$RUN_ID}

log() { printf '[ext-matrix] %s\n' "$*"; }
die() { printf '[ext-matrix] FATAL: %s\n' "$*" >&2; exit 2; }

sanitize() { printf '%s' "$1" | LC_ALL=C tr -c 'A-Za-z0-9._-' '_'; }

valid_fec() {
    case "$1" in
        off|adaptive) return 0 ;;
        [0-9]*:[0-9]*) return 0 ;;
        *) return 1 ;;
    esac
}

read -r -a IMPLS <<< "$IMPL_LIST"
read -r -a FECS <<< "$FEC_LIST"
read -r -a LOSSES <<< "$LOSS_LIST"
read -r -a DIRS <<< "$DIR_LIST"

[ "${#IMPLS[@]}" -gt 0 ] || die "IMPL_LIST is empty"
[ "${#FECS[@]}" -gt 0 ] || die "FEC_LIST is empty"
[ "${#LOSSES[@]}" -gt 0 ] || die "LOSS_LIST is empty"
[ "${#DIRS[@]}" -gt 0 ] || die "DIR_LIST is empty"

for impl in "${IMPLS[@]}"; do
    [ "$impl" = "rust" ] || [ "$impl" = "kernel" ] || [ "$impl" = "rust2" ] || die "bad IMPL_LIST value: $impl"
done
for dir in "${DIRS[@]}"; do
    [ "$dir" = "k0" ] || [ "$dir" = "k1" ] || die "bad DIR_LIST value: $dir"
done
for fec in "${FECS[@]}"; do
    valid_fec "$fec" || die "bad FEC_LIST value: $fec"
done
for loss in "${LOSSES[@]}"; do
    case "$loss" in
        ''|*[!0-9.]*) die "bad LOSS_LIST value: $loss" ;;
    esac
done

TOTAL=$(( ${#IMPLS[@]} * ${#FECS[@]} * ${#LOSSES[@]} * ${#DIRS[@]} ))
SETUP_EST=${SETUP_EST:-8}
EST_SECONDS=$(( TOTAL * (2 * DUR + SETUP_EST) ))

run_tag() {
    local impl=$1 dir=$2 fec=$3 loss=$4
    sanitize "${TAG}-${impl}-${dir}-fec${fec}-l${loss}"
}

if [ "$PLAN_ONLY" = "1" ]; then
    log "plan only: $TOTAL runs, no traffic"
    log "axes: impl={$IMPL_LIST} dir={$DIR_LIST} fec={$FEC_LIST} loss={$LOSS_LIST}"
    log "env: DUR=$DUR UMTU=$UMTU TUNMTU=$TUNMTU NETEM_BOTH=$NETEM_BOTH NETEM_DELAY=$NETEM_DELAY NETEM_RATE=${NETEM_RATE:-0} SKIP_PING=$SKIP_PING"
    log "estimate: ~$EST_SECONDS s (~$(( EST_SECONDS / 60 )) min) with DUR=$DUR"
    n=0
    for impl in "${IMPLS[@]}"; do
        for dir in "${DIRS[@]}"; do
            for fec in "${FECS[@]}"; do
                for loss in "${LOSSES[@]}"; do
                    n=$((n + 1))
                    printf 'PLAN %d/%d tag=%s impl=%s dir=%s fec=%s loss=%s\n' \
                        "$n" "$TOTAL" "$(run_tag "$impl" "$dir" "$fec" "$loss")" \
                        "$impl" "$dir" "$fec" "$loss"
                done
            done
        done
    done
    log "PLAN_ONLY done: $TOTAL runs"
    exit 0
fi

[ "$(id -u)" -eq 0 ] || die "root is required"
[ -f "$WIRE" ] || die "wire-ext.sh not found: $WIRE"
command -v python3 >/dev/null 2>&1 || die "python3 not found"

mkdir -p "$LOG_DIR" "$(dirname "$OUT")"
printf 'tag,impl,dir,fec,loss,tcp_mbit,udp_mbit,udp_loss,ping_loss,frag,result\n' > "$OUT"

field() {
    local key=$1 line=$2 token
    for token in $line; do
        case "$token" in
            "$key"=*) printf '%s' "${token#*=}"; return 0 ;;
        esac
    done
    printf '%s' "-"
}

log "start: $TOTAL runs, csv=$OUT logs=$LOG_DIR"
log "axes: impl={$IMPL_LIST} dir={$DIR_LIST} fec={$FEC_LIST} loss={$LOSS_LIST}"

n=0
ok=0
failed=0
SECONDS=0

for impl in "${IMPLS[@]}"; do
    for dir in "${DIRS[@]}"; do
        for fec in "${FECS[@]}"; do
            for loss in "${LOSSES[@]}"; do
                n=$((n + 1))
                ptag=$(run_tag "$impl" "$dir" "$fec" "$loss")
                run_log="$LOG_DIR/$ptag.log"
                wire_out="$LOG_DIR/$ptag-wire"
                log "[$n/$TOTAL] start $ptag"
                run_start=$SECONDS
                env IMPL="$impl" DIR="$dir" \
                    KFEC="$fec" RFEC="$fec" \
                    NETEM_LOSS="$loss" NETEM_DELAY="$NETEM_DELAY" \
                    NETEM_RATE="$NETEM_RATE" NETEM_BOTH="$NETEM_BOTH" \
                    UMTU="$UMTU" TUNMTU="$TUNMTU" DUR="$DUR" \
                    TAG="$ptag" SKIP_PING="$SKIP_PING" KEEP="$KEEP" OUT="$wire_out" \
                    bash "$WIRE" >"$run_log" 2>&1
                rc=$?
                elapsed=$((SECONDS - run_start))
                res=$(sed -n 's/^RESULT //p' "$run_log" | tail -1)
                if [ -z "$res" ]; then
                    tcp=FAIL
                    udp=FAIL
                    udp_loss=FAIL
                    ping_loss=FAIL
                    frag=-
                    result="FAIL_RC_$rc"
                else
                    tcp=$(field tcp_mbit "$res")
                    udp=$(field udp_mbit "$res")
                    udp_loss=$(field udp_loss "$res")
                    ping_loss=$(field ping_loss "$res")
                    frag=$(field frag "$res")
                    result=$(field result "$res")
                fi
                printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
                    "$ptag" "$impl" "$dir" "$fec" "$loss" \
                    "$tcp" "$udp" "$udp_loss" "$ping_loss" "$frag" "$result" >> "$OUT"
                if [ "$result" = "OK" ]; then
                    ok=$((ok + 1))
                else
                    failed=$((failed + 1))
                fi
                log "[$n/$TOTAL] done ${elapsed}s result=$result tcp=$tcp udp=$udp udp_loss=$udp_loss frag=$frag"
                if [ "$FAILFAST" = "1" ] && [ "$result" != "OK" ]; then
                    log "FAILFAST=1: stop after $result"
                    break 4
                fi
            done
        done
    done
done

log "done: $((ok + failed))/$TOTAL runs, ok=$ok failed=$failed, csv=$OUT"
log "logs: $LOG_DIR"

python3 - "$OUT" <<'PY'
import csv
import statistics
import sys

path = sys.argv[1]
with open(path, newline="") as handle:
    rows = list(csv.DictReader(handle))


def number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def median(values):
    numbers = [value for value in (number(item) for item in values) if value is not None]
    return statistics.median(numbers) if numbers else None


def show(value, digits=1):
    return "-" if value is None else f"{value:.{digits}f}"


if not rows:
    print("summary: no rows")
    raise SystemExit(0)

ok = sum(1 for row in rows if row.get("result") == "OK")
fragmented = [row for row in rows if row.get("frag") not in (None, "", "-", "0")]
print("")
print(f"summary: rows={len(rows)} ok={ok} failed={len(rows) - ok} fragmented={len(fragmented)}")
print(f"{'impl':<7} {'fec':<9} {'loss':>4} {'n':>2} {'tcp_mbit':>9} {'udp_mbit':>9} {'udp_loss%':>9}")
groups = {}
for row in rows:
    key = (row.get("impl", "?"), row.get("fec", "?"), row.get("loss", "?"))
    groups.setdefault(key, []).append(row)


def sort_key(key):
    try:
        loss = float(key[2])
    except ValueError:
        loss = -1.0
    return (key[0], key[1], loss)


for key in sorted(groups, key=sort_key):
    group = groups[key]
    tcp = median(row.get("tcp_mbit") for row in group)
    udp = median(row.get("udp_mbit") for row in group)
    uloss = median(row.get("udp_loss") for row in group)
    print(f"{key[0]:<7} {key[1]:<9} {key[2]:>4} {len(group):>2} "
          f"{show(tcp):>9} {show(udp):>9} {show(uloss, 2):>9}")

if fragmented:
    print("fragmented: " + ", ".join(row.get("tag", "?") for row in fragmented))
bad = [row for row in rows if row.get("result") != "OK"]
if bad:
    print("failed: " + ", ".join(f"{row.get('tag', '?')}={row.get('result', '?')}" for row in bad))
PY

[ "$failed" -eq 0 ]
