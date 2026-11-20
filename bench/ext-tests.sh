#!/bin/bash
set -uo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
WIRE=${WIRE:-$HERE/wire-ext.sh}

DUR=${DUR:-2}
KEEP=${KEEP:-0}
FAILFAST=${FAILFAST:-0}
PLAN_ONLY=${PLAN_ONLY:-0}
SKIP_PING=${SKIP_PING:-0}
UMTU=${UMTU:-${UNDERLAY_MTU:-9000}}
TUNMTU=${TUNMTU:-${TUN_MTU:-1420}}
NETEM_BOTH=${NETEM_BOTH:-1}
UDP_RATE=${UDP_RATE:-400M}
DIR=${DIR:-k0}

MIN_TCP_CLEAN_FEC=${MIN_TCP_CLEAN_FEC:-1000}
MIN_TCP_BBR_FEC=${MIN_TCP_BBR_FEC:-500}
MAX_UDP_LOSS_FEC=${MAX_UDP_LOSS_FEC:-1}
MAX_UDP_LOSS_CLEAN=${MAX_UDP_LOSS_CLEAN:-0.2}
MATCH_UDP_LOSS_MIN=${MATCH_UDP_LOSS_MIN:-1}
MATCH_UDP_LOSS_MAX=${MATCH_UDP_LOSS_MAX:-4}
ADAPTIVE_TCP_TOL=${ADAPTIVE_TCP_TOL:-0.12}
MAX_PING_LOSS_LOSSY=${MAX_PING_LOSS_LOSSY:-20}
SETUP_EST=${SETUP_EST:-9}

CASES=${CASES:-"mixed-fec21 kernel-fec21 profile-mismatch adaptive-clean bbr-fec-clean clean-fec21"}

RUN_ID=${RUN_ID:-$(date +%Y%m%d-%H%M%S)}
LOG_DIR=${LOG_DIR:-$HERE/tmp/ext-tests-$RUN_ID}

RUN_TAG=${RUN_TAG:-$RUN_ID}

log() { printf '[ext-tests] %s\n' "$*"; }
die() { printf '[ext-tests] FATAL: %s\n' "$*" >&2; exit 2; }

sanitize() { printf '%s' "$1" | LC_ALL=C tr -c 'A-Za-z0-9._-' '_'; }
join() { local IFS=' '; printf '%s' "$*"; }

read -r -a CASE_LIST <<< "$CASES"
[ "${#CASE_LIST[@]}" -gt 0 ] || die "CASES is empty"

known_case() {
    case "$1" in
        mixed-fec21|kernel-fec21|profile-mismatch|adaptive-clean|bbr-fec-clean|clean-fec21) return 0 ;;
        *) return 1 ;;
    esac
}

runs_of() {
    case "$1" in
        adaptive-clean) printf '2' ;;
        *) printf '1' ;;
    esac
}

for name in "${CASE_LIST[@]}"; do
    known_case "$name" || die "unknown case: $name"
done

RUNS_TOTAL=0
for name in "${CASE_LIST[@]}"; do
    RUNS_TOTAL=$(( RUNS_TOTAL + $(runs_of "$name") ))
done
EST_SECONDS=$(( RUNS_TOTAL * (2 * DUR + SETUP_EST) ))

print_plan() {
    local n=0 runs
    log "plan only: ${#CASE_LIST[@]} cases, $RUNS_TOTAL runs, no traffic"
    log "env: DUR=$DUR DIR=$DIR UMTU=$UMTU TUNMTU=$TUNMTU NETEM_BOTH=$NETEM_BOTH UDP_RATE=$UDP_RATE SKIP_PING=$SKIP_PING KEEP=$KEEP"
    log "thresholds: MIN_TCP_CLEAN_FEC=$MIN_TCP_CLEAN_FEC MIN_TCP_BBR_FEC=$MIN_TCP_BBR_FEC MAX_UDP_LOSS_FEC=$MAX_UDP_LOSS_FEC MAX_UDP_LOSS_CLEAN=$MAX_UDP_LOSS_CLEAN MATCH_UDP_LOSS=[$MATCH_UDP_LOSS_MIN..$MATCH_UDP_LOSS_MAX] ADAPTIVE_TCP_TOL=$ADAPTIVE_TCP_TOL"
    for name in "${CASE_LIST[@]}"; do
        runs=$(runs_of "$name")
        for i in $(seq 1 "$runs"); do
            n=$((n + 1))
            printf 'PLAN %d/%d case=%s run=%d/%d\n' "$n" "$RUNS_TOTAL" "$name" "$i" "$runs"
        done
        case "$name" in
            mixed-fec21) printf 'PLAN   command: IMPL=rust KFEC=2:1 RFEC=2:1 NETEM_LOSS=2\n' ;;
            kernel-fec21) printf 'PLAN   command: IMPL=kernel KFEC=2:1 NETEM_LOSS=2\n' ;;
            profile-mismatch) printf 'PLAN   command: IMPL=rust KFEC=2:1 RFEC=8:2 NETEM_LOSS=2\n' ;;
            adaptive-clean) printf 'PLAN   command: IMPL=rust KFEC=off RFEC=off NETEM_LOSS=0; IMPL=rust KFEC=adaptive RFEC=adaptive NETEM_LOSS=0\n' ;;
            bbr-fec-clean) printf 'PLAN   command: IMPL=rust KFEC=2:1 RFEC=2:1 KBBR=on RBBR=on NETEM_LOSS=0\n' ;;
            clean-fec21) printf 'PLAN   command: IMPL=kernel KFEC=2:1 NETEM_LOSS=0\n' ;;
        esac
    done
    log "estimate: ~$EST_SECONDS s (~$(( (EST_SECONDS + 59) / 60 )) min) with DUR=$DUR"
    log "PLAN_ONLY done: ${#CASE_LIST[@]} cases, $RUNS_TOTAL runs"
}

if [ "$PLAN_ONLY" = "1" ]; then
    print_plan
    exit 0
fi

[ "$(id -u)" -eq 0 ] || die "root is required (netns, insmod, tcpdump); use PLAN_ONLY=1 for a dry run"
[ -f "$WIRE" ] || die "wire-ext.sh not found: $WIRE"
command -v python3 >/dev/null 2>&1 || die "python3 not found"
[ "$DUR" -ge 1 ] 2>/dev/null || die "DUR must be a positive integer"

mkdir -p "$LOG_DIR"

R_LINE=""
R_TCP="FAIL"
R_UDP="FAIL"
R_UDPLOSS="FAIL"
R_PING="FAIL"
R_FRAG="-"
R_RESULT="FAIL"
R_ELAPSED=0

run_wire() {
    local tag=$1 impl=$2 kfec=$3 rfec=$4 kbbr=$5 rbbr=$6 loss=$7
    local safe log_file wire_out rc start
    safe=$(sanitize "$tag")
    log_file="$LOG_DIR/$safe.log"
    wire_out="$LOG_DIR/$safe-wire"
    RUNS_DONE=$((RUNS_DONE + 1))
    log "[$RUNS_DONE/$RUNS_TOTAL] run $safe impl=$impl fec=$kfec/$rfec bbr=$kbbr/$rbbr loss=$loss"
    start=$SECONDS
    env IMPL="$impl" DIR="$DIR" \
        KFEC="$kfec" RFEC="$rfec" KBBR="$kbbr" RBBR="$rbbr" \
        NETEM_LOSS="$loss" NETEM_BOTH="$NETEM_BOTH" \
        UMTU="$UMTU" TUNMTU="$TUNMTU" DUR="$DUR" UDP_RATE="$UDP_RATE" \
        TAG="$safe" SKIP_PING="$SKIP_PING" KEEP="$KEEP" OUT="$wire_out" \
        bash "$WIRE" >"$log_file" 2>&1
    rc=$?
    R_ELAPSED=$((SECONDS - start))
    R_LINE=$(sed -n 's/^RESULT //p' "$log_file" | tail -1)
    if [ -z "$R_LINE" ]; then
        R_TCP=FAIL
        R_UDP=FAIL
        R_UDPLOSS=FAIL
        R_PING=FAIL
        R_FRAG=-
        R_RESULT="FAIL_RC_$rc"
        log "[$RUNS_DONE/$RUNS_TOTAL] done ${R_ELAPSED}s result=$R_RESULT (no RESULT line: $(tail -1 "$log_file" 2>/dev/null))"
    else
        R_TCP=$(field tcp_mbit "$R_LINE")
        R_UDP=$(field udp_mbit "$R_LINE")
        R_UDPLOSS=$(field udp_loss "$R_LINE")
        R_PING=$(field ping_loss "$R_LINE")
        R_FRAG=$(field frag "$R_LINE")
        R_RESULT=$(field result "$R_LINE")
        log "[$RUNS_DONE/$RUNS_TOTAL] done ${R_ELAPSED}s result=$R_RESULT tcp=$R_TCP udp=$R_UDP udp_loss=$R_UDPLOSS ping=$R_PING frag=$R_FRAG"
    fi
}

field() {
    local key=$1 line=$2 token
    for token in $line; do
        case "$token" in
            "$key"=*) printf '%s' "${token#*=}"; return 0 ;;
        esac
    done
    printf '%s' "-"
}

is_num() {
    case "$1" in
        ''|FAIL|SKIP|'-') return 1 ;;
    esac
    case "$1" in
        *[!0-9.]*) return 1 ;;
    esac
    return 0
}

cmp() {
    local op=$1 a=$2 b=$3
    awk -v a="$a" -v b="$b" -v op="$op" 'BEGIN {
        if (op == "ge") exit !(a + 0 >= b + 0)
        if (op == "gt") exit !(a + 0 > b + 0)
        if (op == "le") exit !(a + 0 <= b + 0)
        if (op == "lt") exit !(a + 0 < b + 0)
        if (op == "eq") exit !(a + 0 == b + 0)
        exit 1
    }'
}

INFO=()
FAILS=()

info() { INFO+=("$*"); }
fail() { FAILS+=("$*"); }

chk_cmp() {
    local label=$1 op=$2 value=$3 limit=$4 sym
    case "$op" in
        ge) sym='>=' ;;
        gt) sym='>' ;;
        le) sym='<=' ;;
        lt) sym='<' ;;
        eq) sym='==' ;;
        *) sym="$op" ;;
    esac
    if ! is_num "$value"; then
        fail "$label=$value (нет данных)"
        return 1
    fi
    if cmp "$op" "$value" "$limit"; then
        info "$label=$value$sym$limit"
        return 0
    fi
    fail "$label=$value (нужно $sym$limit)"
    return 1
}

chk_result() {
    if [ "$R_RESULT" = "OK" ]; then
        info "result=OK"
        return 0
    fi
    fail "result=$R_RESULT"
    return 1
}

chk_ping() {
    if [ "$SKIP_PING" = "1" ]; then
        info "ping=SKIP"
        return 0
    fi
    chk_cmp ping_loss eq "$R_PING" 0
}

chk_ping_lossy() {
    if [ "$SKIP_PING" = "1" ]; then
        info "ping=SKIP"
        return 0
    fi
    chk_cmp ping_loss le "$R_PING" "$MAX_PING_LOSS_LOSSY"
}

chk_frag() {
    if [ "$R_FRAG" = "-" ]; then
        info "frag=SKIP (tcpdump недоступен)"
        return 0
    fi
    chk_cmp frag eq "$R_FRAG" 0
}

case_mixed_fec21() {
    run_wire "$RUN_TAG-mixed-fec21" rust 2:1 2:1 off off 2
    chk_result || return 0
    chk_cmp tcp gt "$R_TCP" 0
    chk_cmp udp_loss lt "$R_UDPLOSS" "$MAX_UDP_LOSS_FEC"
    chk_ping_lossy
    chk_frag
}

case_kernel_fec21() {
    run_wire "$RUN_TAG-kernel-fec21" kernel 2:1 2:1 off off 2
    chk_result || return 0
    chk_cmp tcp gt "$R_TCP" 0
    chk_cmp udp_loss lt "$R_UDPLOSS" "$MAX_UDP_LOSS_FEC"
    chk_ping_lossy
    chk_frag
}

case_profile_mismatch() {
    run_wire "$RUN_TAG-profile-mismatch" rust 2:1 8:2 off off 2
    chk_result || return 0
    chk_cmp tcp gt "$R_TCP" 0
    chk_cmp udp_loss ge "$R_UDPLOSS" "$MATCH_UDP_LOSS_MIN"
    chk_cmp udp_loss le "$R_UDPLOSS" "$MATCH_UDP_LOSS_MAX"
    chk_ping
    chk_frag
}

case_adaptive_clean() {
    local legacy_tcp adaptive_tcp floor
    run_wire "$RUN_TAG-adaptive-clean-legacy" rust off off off off 0
    chk_result || return 0
    legacy_tcp=$R_TCP
    chk_cmp udp_loss lt "$R_UDPLOSS" "$MAX_UDP_LOSS_CLEAN"
    chk_cmp tcp gt "$legacy_tcp" 0
    if ! is_num "$legacy_tcp"; then
        fail "legacy_tcp=$legacy_tcp (нет данных)"
        return 0
    fi
    run_wire "$RUN_TAG-adaptive-clean-adaptive" rust adaptive adaptive off off 0
    chk_result || return 0
    adaptive_tcp=$R_TCP
    chk_cmp udp_loss lt "$R_UDPLOSS" "$MAX_UDP_LOSS_CLEAN"
    floor=$(awk -v v="$legacy_tcp" -v tol="$ADAPTIVE_TCP_TOL" 'BEGIN { printf "%.1f", v * (1 - tol) }')
    if is_num "$adaptive_tcp"; then
        info "tcp_legacy=$legacy_tcp tcp_adaptive=$adaptive_tcp floor=$floor"
    fi
    chk_cmp tcp_adaptive ge "$adaptive_tcp" "$floor"
    chk_frag
}

case_bbr_fec_clean() {
    run_wire "$RUN_TAG-bbr-fec-clean" rust 2:1 2:1 on on 0
    chk_result || return 0
    chk_cmp tcp ge "$R_TCP" "$MIN_TCP_BBR_FEC"
    chk_cmp udp_loss lt "$R_UDPLOSS" "$MAX_UDP_LOSS_CLEAN"
    chk_frag
}

case_clean_fec21() {
    run_wire "$RUN_TAG-clean-fec21" kernel 2:1 2:1 off off 0
    chk_result || return 0
    chk_cmp tcp ge "$R_TCP" "$MIN_TCP_CLEAN_FEC"
    chk_cmp udp_loss lt "$R_UDPLOSS" "$MAX_UDP_LOSS_CLEAN"
    chk_frag
}

run_case() {
    local name=$1 fn="case_${1//-/_}"
    INFO=()
    FAILS=()
    CASE_START=$SECONDS
    if ! declare -F "$fn" >/dev/null 2>&1; then
        log "CASE $name FAIL  failed=[нет реализации $fn]"
        CASE_FAILED=1
        return 1
    fi
    "$fn"
    CASE_SECONDS=$((SECONDS - CASE_START))
    if [ "${#FAILS[@]}" -eq 0 ]; then
        CASE_FAILED=0
        log "CASE $name PASS  ${CASE_SECONDS}s  info=[$(join "${INFO[@]}")]"
        return 0
    fi
    CASE_FAILED=1
    log "CASE $name FAIL  ${CASE_SECONDS}s  failed=[$(join "${FAILS[@]}")]"
    [ "${#INFO[@]}" -gt 0 ] && log "    info=[$(join "${INFO[@]}")]"
    return 1
}

[ "$KEEP" = "1" ] && [ "$RUNS_TOTAL" -gt 1 ] && \
    log "WARN: KEEP=1 оставляет netns/модуль/демон после каждого прогона, следующие прогоны могут упасть; используйте CASES"

log "start: ${#CASE_LIST[@]} cases, $RUNS_TOTAL runs, dur=$DUR dir=$DIR logs=$LOG_DIR"
log "cases: $(join "${CASE_LIST[@]}")"

RUNS_DONE=0
CASES_PASS=0
CASES_FAIL=0
FAILED_CASES=()
SECONDS=0

for name in "${CASE_LIST[@]}"; do
    run_case "$name"
    if [ "$CASE_FAILED" -eq 0 ]; then
        CASES_PASS=$((CASES_PASS + 1))
    else
        CASES_FAIL=$((CASES_FAIL + 1))
        FAILED_CASES+=("$name")
        if [ "$FAILFAST" = "1" ]; then
            log "FAILFAST=1: stop after $name"
            break
        fi
    fi
done

TOTAL_SECONDS=$SECONDS
log "done: cases=$((CASES_PASS + CASES_FAIL))/${#CASE_LIST[@]} pass=$CASES_PASS fail=$CASES_FAIL runs=$RUNS_DONE/$RUNS_TOTAL in ${TOTAL_SECONDS}s"
[ "${#FAILED_CASES[@]}" -gt 0 ] && log "failed cases: $(join "${FAILED_CASES[@]}")"
log "logs: $LOG_DIR"

[ "$CASES_FAIL" -eq 0 ]
