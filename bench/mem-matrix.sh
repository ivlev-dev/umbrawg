#!/bin/bash
set -euo pipefail

BENCH_DIR=${BENCH_DIR:-$(cd "$(dirname "$0")" && pwd)}
PARENT_DIR=$(cd "$BENCH_DIR/.." && pwd)
if [ -d "$PARENT_DIR/umbrawg-rs" ] || [ -d "$PARENT_DIR/umbrawg-tools" ] ||
    [ -d "$PARENT_DIR/umbrawg-linux-kernel-module" ]; then
    REPO_ROOT=$PARENT_DIR
    WORKSPACE_ROOT=$PARENT_DIR
else
    REPO_ROOT=$PARENT_DIR
    WORKSPACE_ROOT=$(cd "$PARENT_DIR/.." && pwd)
fi
. "$BENCH_DIR/bench-lib.sh"

RUSTDIR=${RUSTDIR:-$(first_existing_dir "$WORKSPACE_ROOT/umbrawg-rs" "$WORKSPACE_ROOT/rust")}
MODDIR=${MODDIR:-${MODULE_DIR:-$(first_existing_dir "$WORKSPACE_ROOT/umbrawg-linux-kernel-module/src" "$WORKSPACE_ROOT/module/src")}}
UWG=${UWG:-$(first_existing_file "$REPO_ROOT/target/release/uwg" "$WORKSPACE_ROOT/umbrawg-tools/target/release/uwg" "$WORKSPACE_ROOT/tools/target/release/uwg")}
DAEMON=${DAEMON:-$(first_existing_file "$RUSTDIR/target/release/umbrawg" "$RUSTDIR/umbrawg")}
GO_BASELINE=${GO_BASELINE:-$(first_existing_file /opt/baseline/amneziawg-go /usr/local/bin/amneziawg-go /usr/bin/amneziawg-go)}
AWG=${AWG:-awg}
OBF=${OBF:-$BENCH_DIR/obf-params.conf}

IMPL_LIST=${IMPL_LIST-"kernel-umbrawg kernel-amneziawg rust go"}
FEC_LIST=${FEC_LIST-"off adaptive 2:1 8:2"}
PEERS_LIST=${PEERS_LIST-"1 4 16"}
LOAD_LIST=${LOAD_LIST-"idle tcp"}
OBF_LIST=${OBF_LIST-"0 1"}
REPEATS=${REPEATS:-2}
SETTLE=${SETTLE:-2}
RUN=${RUN:-5}

PLAN_ONLY=${PLAN_ONLY:-0}
FORCE=${FORCE:-0}
IDLE_LOAD_MAX=${IDLE_LOAD_MAX:-1.0}
UNDERLAY_MTU=${UNDERLAY_MTU:-9000}
TUN_MTU=${TUN_MTU:-1420}
RUN_ID=${RUN_ID:-$(date +%Y%m%d-%H%M%S)}
OUT=${OUT:-$BENCH_DIR/tmp/mem-$RUN_ID.csv}
DIAG=${DIAG:-$BENCH_DIR/tmp/mem-$RUN_ID.diag}
LOG_DIR=${LOG_DIR:-$BENCH_DIR/tmp/mem-$RUN_ID}
LOCK=${LOCK:-/tmp/uwg-bench.lock}

NS0=mem0
NS1=mem1
IF0=uwgm0
IF1=uwgm1
V0=mveth0
V1=mveth1
UL0=192.168.78.1
UL1=192.168.78.2
TUN0=10.10.0.1
TUN1=10.10.0.2
PORT0=54820
PORT1=54821
IPERF_PORT=5401
SRV_PIDFILE=/tmp/mem-matrix-srv.pid
SRV_LOG=/tmp/mem-matrix-srv.log

RESULT_HEADER="impl,fec,peers,load,obf,repeats,rss_kb_sum,rss_kb_per_proc,pss_kb,slab_delta_kb,per_peer_kb"

DAEMON_PIDS=()
CONF0=""
CONF1=""
SRV_PID=""
CLIENT_PID=""
CELL_TAG=""
PEERS_CUR=0
WE_INSMOD_UMBRAWG=0
WE_MODPROBE_AMNEZIAWG=0
HARNESS_STARTED=0
POSTFLIGHT_DONE=0
MODS_AT_START=""
NETNS_AT_START=""
IPERF_AT_START=""

K_SLAB=0
K_SUNRE=0
K_MEMAVAIL=0
BASE_SLAB=0
BASE_SUNRE=0
BASE_MEMAVAIL=0
BASE_SLABFILE=""
ROW_SLABFILE=""
SLAB_DIFF_DONE=0
SLAB_CHANGED=0
SLAB_TOP="-"

ROW_SLAB_DELTA=""
ROW_PER_PEER=""
ROW_RSS_SUM=""
ROW_RSS_PER=""
ROW_PSS=""
US_RSS=()
US_HWM=()
US_PSS=()
US_PD=()

log() { printf '[mem-matrix] %s\n' "$*"; }
die() { printf '[mem-matrix] FATAL: %s\n' "$*" >&2; exit 2; }

sanitize() { printf '%s' "$1" | LC_ALL=C tr -c 'A-Za-z0-9._-' '_'; }

valid_fec() {
    case "$1" in
        off|adaptive) return 0 ;;
        [0-9]*:[0-9]*) return 0 ;;
        *) return 1 ;;
    esac
}

is_uint() {
    case "${1:-}" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

is_num() {
    [[ "${1:-}" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

is_kernel_impl() {
    case "$1" in
        kernel-umbrawg|kernel-amneziawg) return 0 ;;
        *) return 1 ;;
    esac
}

read -r -a IMPLS <<<"$IMPL_LIST"
read -r -a FECS <<<"$FEC_LIST"
read -r -a PEERS <<<"$PEERS_LIST"
read -r -a LOADS <<<"$LOAD_LIST"
read -r -a OBFS <<<"$OBF_LIST"

[ "${#IMPLS[@]}" -gt 0 ] || die "IMPL_LIST is empty"
[ "${#FECS[@]}" -gt 0 ] || die "FEC_LIST is empty"
[ "${#PEERS[@]}" -gt 0 ] || die "PEERS_LIST is empty"
[ "${#LOADS[@]}" -gt 0 ] || die "LOAD_LIST is empty"
[ "${#OBFS[@]}" -gt 0 ] || die "OBF_LIST is empty"
is_uint "$REPEATS" && [ "$REPEATS" -ge 1 ] || die "REPEATS must be a positive integer"
is_num "$SETTLE" || die "SETTLE must be a number of seconds"
is_uint "$RUN" && [ "$RUN" -ge 1 ] || die "RUN must be a positive integer"

for impl in "${IMPLS[@]}"; do
    case "$impl" in
        kernel-umbrawg|kernel-amneziawg|rust|go) ;;
        *) die "bad IMPL_LIST value: $impl" ;;
    esac
done
for fec in "${FECS[@]}"; do
    valid_fec "$fec" || die "bad FEC_LIST value: $fec"
done
for peers in "${PEERS[@]}"; do
    is_uint "$peers" && [ "$peers" -ge 1 ] && [ "$peers" -le 200 ] ||
        die "bad PEERS_LIST value: $peers (1..200)"
done
for load in "${LOADS[@]}"; do
    case "$load" in
        idle|tcp) ;;
        *) die "bad LOAD_LIST value: $load (idle|tcp)" ;;
    esac
done
for obf in "${OBFS[@]}"; do
    case "$obf" in
        0|1) ;;
        *) die "bad OBF_LIST value: $obf (0|1)" ;;
    esac
done

fec_values_for() {
    case "$1" in
        kernel-umbrawg|rust) printf '%s\n' "${FECS[@]}" ;;
        *) printf 'none\n' ;;
    esac
}

TOTAL_CELLS=0
TOTAL_RUNS=0
IDLE_RUNS=0
TCP_RUNS=0
for impl in "${IMPLS[@]}"; do
    fec_count=0
    for _fec in $(fec_values_for "$impl"); do
        fec_count=$((fec_count + 1))
    done
    cells=$((fec_count * ${#OBFS[@]} * ${#PEERS[@]}))
    idle_count=0
    tcp_count=0
    for load in "${LOADS[@]}"; do
        if [ "$load" = "idle" ]; then
            idle_count=$((idle_count + 1))
        else
            tcp_count=$((tcp_count + 1))
        fi
    done
    TOTAL_CELLS=$((TOTAL_CELLS + cells))
    TOTAL_RUNS=$((TOTAL_RUNS + cells * REPEATS * ${#LOADS[@]}))
    IDLE_RUNS=$((IDLE_RUNS + cells * REPEATS * idle_count))
    TCP_RUNS=$((TCP_RUNS + cells * REPEATS * tcp_count))
done
SETUP_EST=${SETUP_EST:-4}
EST_SECONDS=$(awk -v cells="$TOTAL_CELLS" -v idle="$IDLE_RUNS" -v tcp="$TCP_RUNS" \
    -v setup="$SETUP_EST" -v settle="$SETTLE" -v run="$RUN" \
    'BEGIN { printf "%d", cells * setup + idle * settle + tcp * (run + 1) }')

print_plan() {
    local n=0 impl fec obf peers repeat load cell_fecs=()
    log "plan only: $TOTAL_RUNS runs in $TOTAL_CELLS cells; no root, no traffic"
    log "axes: impl={$IMPL_LIST} fec={$FEC_LIST} peers={$PEERS_LIST} load={$LOAD_LIST} obf={$OBF_LIST}"
    log "env: REPEATS=$REPEATS SETTLE=${SETTLE}s RUN=${RUN}s underlay_mtu=$UNDERLAY_MTU tun_mtu=$TUN_MTU"
    log "estimate: ~${EST_SECONDS}s (~$((EST_SECONDS / 60)) min), setup≈${SETUP_EST}s per cell"
    log "csv: $OUT"
    log "diag: $DIAG"
    log "logs: $LOG_DIR"
    for impl in "${IMPLS[@]}"; do
        mapfile -t cell_fecs < <(fec_values_for "$impl")
        for fec in "${cell_fecs[@]}"; do
            for obf in "${OBFS[@]}"; do
                for peers in "${PEERS[@]}"; do
                    for repeat in $(seq 1 "$REPEATS"); do
                        for load in "${LOADS[@]}"; do
                            n=$((n + 1))
                            printf 'PLAN %d/%d impl=%s fec=%s peers=%s obf=%s repeat=%s load=%s\n' \
                                "$n" "$TOTAL_RUNS" "$impl" "$fec" "$peers" "$obf" "$repeat" "$load"
                        done
                    done
                done
            done
        done
    done
    log "PLAN_ONLY done: $TOTAL_RUNS runs"
}

if [ "$PLAN_ONLY" = "1" ]; then
    print_plan
    exit 0
fi

[ "$(id -u)" -eq 0 ] || die "root is required (netns, modules, /proc/slabinfo)"

require_tools() {
    local missing="" impl cmd
    [ -f "$OBF" ] || missing="$missing obf=$OBF"
    [ -x "$UWG" ] || missing="$missing uwg=$UWG"
    for cmd in ip ss iperf3 python3 ping; do
        command -v "$cmd" >/dev/null 2>&1 || missing="$missing cmd:$cmd"
    done
    for impl in "${IMPLS[@]}"; do
        case "$impl" in
            kernel-umbrawg)
                [ -f "$MODDIR/umbrawg.ko" ] || missing="$missing kernel-umbrawg=$MODDIR/umbrawg.ko"
                ;;
            kernel-amneziawg)
                command -v "$AWG" >/dev/null 2>&1 || missing="$missing awg=$AWG"
                ;;
            rust)
                [ -x "$DAEMON" ] || missing="$missing rust=$DAEMON"
                ;;
            go)
                [ -x "$GO_BASELINE" ] || missing="$missing go=$GO_BASELINE"
                command -v "$AWG" >/dev/null 2>&1 || missing="$missing awg=$AWG"
                ;;
        esac
    done
    if [ -n "$missing" ]; then
        echo "REQUIRE_FAILED:$missing" >&2
        echo "REQUIRE_HINT: задай UWG, MODDIR, DAEMON, GO_BASELINE, AWG, OBF; пути по умолчанию — см. bench/README.md" >&2
        exit 5
    fi
}

mem_busy_reasons() {
    local self_pid=$1 reasons=() l1 mods nets p
    l1=$(awk '{print $1}' /proc/loadavg)
    if awk -v l="$l1" -v m="$IDLE_LOAD_MAX" 'BEGIN { exit !(l > m) }'; then
        reasons+=("load1=$l1>$IDLE_LOAD_MAX")
    fi
    if pgrep -x iperf3 >/dev/null 2>&1; then
        reasons+=("iperf3=$(pgrep -x iperf3 | tr '\n' ',' | sed 's/,$//')")
    fi
    mods=$(lsmod | awk '$1 == "umbrawg" || $1 == "amneziawg" { print $1 }' | tr '\n' ',' | sed 's/,$//')
    if [ -n "$mods" ]; then
        reasons+=("modules=$mods")
    fi
    nets=$(ip netns list 2>/dev/null |
        awk '$1 == "bn0" || $1 == "bn1" || $1 == "mem0" || $1 == "mem1" || $1 == "xwg0" || $1 == "xwg1" { print $1 }' |
        tr '\n' ',' | sed 's/,$//')
    if [ -n "$nets" ]; then
        reasons+=("netns=$nets")
    fi
    for p in $(pgrep -f "bench/bench.sh|bench/mem-matrix.sh|bench/ext-matrix.sh|bench/wire-ext.sh" 2>/dev/null); do
        if [ "$p" != "$self_pid" ]; then
            reasons+=("bench=$p")
        fi
    done
    if [ "${#reasons[@]}" -eq 0 ]; then
        return 0
    fi
    printf '%s\n' "${reasons[@]}"
    return 1
}

idle_guard() {
    local reasons
    if [ "$FORCE" = "1" ]; then
        log "IDLE_GUARD: пропуск проверки, FORCE=1"
        return 0
    fi
    if reasons=$(mem_busy_reasons "$$"); then
        log "IDLE_GUARD: стенд свободен"
        return 0
    fi
    echo "IDLE_GUARD: стенд занят, запуск отменён:" >&2
    printf '  %s\n' $reasons >&2
    echo "IDLE_GUARD: обойди через FORCE=1, если уверен, что замеры не пересекутся" >&2
    exit 3
}

snapshot_state() {
    MODS_AT_START=$(lsmod | awk '$1 == "umbrawg" || $1 == "amneziawg" { print $1 }' | tr '\n' ' ' || true)
    NETNS_AT_START=$(ip netns list 2>/dev/null | awk '{ print $1 }' | tr '\n' ' ' || true)
    IPERF_AT_START=$(pgrep -x iperf3 2>/dev/null | tr '\n' ' ' || true)
}

cleanup() {
    set +e
    local p ns
    if [ -n "${CLIENT_PID:-}" ]; then
        kill "$CLIENT_PID" 2>/dev/null
        wait "$CLIENT_PID" 2>/dev/null
        CLIENT_PID=""
    fi
    if [ -n "${SRV_PID:-}" ]; then
        kill "$SRV_PID" 2>/dev/null
        SRV_PID=""
    fi
    rm -f "$SRV_PIDFILE"
    for p in ${DAEMON_PIDS[@]+"${DAEMON_PIDS[@]}"}; do
        kill "$p" 2>/dev/null
    done
    for p in ${DAEMON_PIDS[@]+"${DAEMON_PIDS[@]}"}; do
        wait "$p" 2>/dev/null
    done
    DAEMON_PIDS=()
    for ns in "$NS0" "$NS1"; do
        if [ -e "/var/run/netns/$ns" ]; then
            for p in $(ip netns pids "$ns" 2>/dev/null); do
                kill "$p" 2>/dev/null
            done
            sleep 0.1
            ip netns del "$ns" 2>/dev/null
        fi
    done
    rm -f "/var/run/umbrawg/$IF0.sock" "/var/run/umbrawg/$IF1.sock"
    rm -f "/var/run/amneziawg/$IF0.sock" "/var/run/amneziawg/$IF1.sock"
    if [ "${WE_INSMOD_UMBRAWG:-0}" = "1" ]; then
        for _ in $(seq 1 10); do
            rmmod umbrawg 2>/dev/null && break
            sleep 0.2
        done
        WE_INSMOD_UMBRAWG=0
    fi
    if [ "${WE_MODPROBE_AMNEZIAWG:-0}" = "1" ]; then
        rmmod amneziawg 2>/dev/null
        WE_MODPROBE_AMNEZIAWG=0
    fi
    if [ -n "${CONF0:-}" ]; then
        rm -f "$CONF0"
    fi
    if [ -n "${CONF1:-}" ]; then
        rm -f "$CONF1"
    fi
    CONF0=""
    CONF1=""
    return 0
}

postflight() {
    local dirty=0 msg="" mod ns pid
    [ "$POSTFLIGHT_DONE" = "1" ] && return 0
    POSTFLIGHT_DONE=1
    if [ "${HARNESS_STARTED:-0}" != "1" ]; then
        return 0
    fi
    for ns in "$NS0" "$NS1"; do
        if ip netns list 2>/dev/null | awk -v n="$ns" '$1 == n { found = 1 } END { exit !found }'; then
            case " $NETNS_AT_START " in
                *" $ns "*) ;;
                *) dirty=1; msg="$msg netns:$ns" ;;
            esac
        fi
    done
    for mod in umbrawg amneziawg; do
        if lsmod | awk -v m="$mod" '$1 == m { found = 1 } END { exit !found }'; then
            case " $MODS_AT_START " in
                *" $mod "*) ;;
                *) dirty=1; msg="$msg module:$mod" ;;
            esac
        fi
    done
    if pgrep -x iperf3 >/dev/null 2>&1; then
        pid=$(pgrep -x iperf3 | head -1)
        case " $IPERF_AT_START " in
            *" $pid "*) ;;
            *) dirty=1; msg="$msg iperf3:$pid" ;;
        esac
    fi
    if [ "$dirty" = "1" ]; then
        echo "POSTFLIGHT: dirty$msg"
        return 1
    fi
    echo "POSTFLIGHT: clean"
    return 0
}

on_exit() {
    local rc=$?
    trap - EXIT
    if [ "${HARNESS_STARTED:-0}" = "1" ]; then
        cleanup
    fi
    set +e
    if ! postflight; then
        if [ "$rc" = "0" ]; then
            rc=4
        fi
    fi
    exit "$rc"
}

uwg_ns() {
    local ns=$1
    shift
    ip netns exec "$ns" "$UWG" "$@"
}

awg_ns() {
    local ns=$1
    shift
    ip netns exec "$ns" "$AWG" "$@"
}

setup_topology() {
    ip netns add "$NS0" || return 1
    ip netns add "$NS1" || return 1
    ip link add "$V0" type veth peer name "$V1" || return 1
    ip link set "$V0" netns "$NS0" || return 1
    ip link set "$V1" netns "$NS1" || return 1
    ip -n "$NS0" link set "$V0" mtu "$UNDERLAY_MTU" || return 1
    ip -n "$NS1" link set "$V1" mtu "$UNDERLAY_MTU" || return 1
    ip -n "$NS0" addr add "$UL0/24" dev "$V0" || return 1
    ip -n "$NS1" addr add "$UL1/24" dev "$V1" || return 1
    ip -n "$NS0" link set "$V0" up || return 1
    ip -n "$NS1" link set "$V1" up || return 1
    ip -n "$NS0" link set lo up || return 1
    ip -n "$NS1" link set lo up || return 1
    return 0
}

wait_socket() {
    local path=$1 tries=50
    for _ in $(seq 1 "$tries"); do
        if [ -S "$path" ]; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

load_module() {
    local impl=$1
    case "$impl" in
        kernel-umbrawg)
            if lsmod | awk '$1 == "umbrawg" { found = 1 } END { exit !found }'; then
                echo "MODULE_ALREADY_LOADED: umbrawg уже загружен, insmod не выполняю" >&2
                return 1
            fi
            modprobe udp_tunnel || return 1
            modprobe ip6_udp_tunnel || return 1
            insmod "$MODDIR/umbrawg.ko" || return 1
            WE_INSMOD_UMBRAWG=1
            ;;
        kernel-amneziawg)
            modprobe udp_tunnel || return 1
            modprobe ip6_udp_tunnel || return 1
            if lsmod | awk '$1 == "amneziawg" { found = 1 } END { exit !found }'; then
                echo "MODULE_REUSED: amneziawg уже загружен" >&2
            else
                modprobe amneziawg || return 1
                WE_MODPROBE_AMNEZIAWG=1
            fi
            ;;
        *)
            return 0
            ;;
    esac
    return 0
}

create_ifaces() {
    local impl=$1
    case "$impl" in
        kernel-umbrawg)
            ip netns exec "$NS0" ip link add "$IF0" type umbrawg || return 1
            ip netns exec "$NS1" ip link add "$IF1" type umbrawg || return 1
            ;;
        kernel-amneziawg)
            ip netns exec "$NS0" ip link add "$IF0" type amneziawg || return 1
            ip netns exec "$NS1" ip link add "$IF1" type amneziawg || return 1
            ;;
        *)
            return 0
            ;;
    esac
    return 0
}

start_impl() {
    local impl=$1 fec=$2
    case "$impl" in
        rust)
            DAEMON_PIDS=()
            env UMBRAWG_FEC="$fec" UMBRAWG_THREADS=1 UMBRAWG_UNDERLAY_MTU="$UNDERLAY_MTU" \
                ip netns exec "$NS0" "$DAEMON" --foreground "$IF0" \
                >"$LOG_DIR/$CELL_TAG-$IF0.log" 2>&1 &
            DAEMON_PIDS+=($!)
            env UMBRAWG_FEC="$fec" UMBRAWG_THREADS=1 UMBRAWG_UNDERLAY_MTU="$UNDERLAY_MTU" \
                ip netns exec "$NS1" "$DAEMON" --foreground "$IF1" \
                >"$LOG_DIR/$CELL_TAG-$IF1.log" 2>&1 &
            DAEMON_PIDS+=($!)
            if ! wait_socket "/var/run/umbrawg/$IF0.sock" ||
                ! wait_socket "/var/run/umbrawg/$IF1.sock"; then
                return 1
            fi
            ;;
        go)
            DAEMON_PIDS=()
            GOMAXPROCS=1 ip netns exec "$NS0" "$GO_BASELINE" -f "$IF0" \
                >"$LOG_DIR/$CELL_TAG-$IF0.log" 2>&1 &
            DAEMON_PIDS+=($!)
            GOMAXPROCS=1 ip netns exec "$NS1" "$GO_BASELINE" -f "$IF1" \
                >"$LOG_DIR/$CELL_TAG-$IF1.log" 2>&1 &
            DAEMON_PIDS+=($!)
            if ! wait_socket "/var/run/amneziawg/$IF0.sock" ||
                ! wait_socket "/var/run/amneziawg/$IF1.sock"; then
                return 1
            fi
            ;;
        *)
            return 1
            ;;
    esac
    return 0
}

make_configs() {
    local impl=$1 fec=$2 obf=$3 peers=$4 out0=$5 out1=$6
    local k0 k1 p0 p1 obfblock extra0 extra1 fecblock i pk0 pk1
    k0=$("$UWG" genkey) || return 1
    k1=$("$UWG" genkey) || return 1
    p0=$(printf '%s' "$k0" | "$UWG" pubkey) || return 1
    p1=$(printf '%s' "$k1" | "$UWG" pubkey) || return 1
    obfblock=""
    if [ "$obf" = "1" ]; then
        obfblock=$(obf_block_from_conf "$OBF" "$UWG" genkey) || return 1
    fi
    fecblock=""
    case "$impl" in
        kernel-umbrawg|rust)
            if [ "$fec" != "none" ]; then
                fecblock="FEC = $fec"
            fi
            ;;
    esac
    extra0=""
    extra1=""
    i=2
    while [ "$i" -le "$peers" ]; do
        pk0=$(printf '%s' "$("$UWG" genkey)" | "$UWG" pubkey) || return 1
        pk1=$(printf '%s' "$("$UWG" genkey)" | "$UWG" pubkey) || return 1
        extra0="$extra0

[Peer]
PublicKey = $pk1
AllowedIPs = 10.99.$i.0/24"
        extra1="$extra1

[Peer]
PublicKey = $pk0
AllowedIPs = 10.98.$i.0/24"
        i=$((i + 1))
    done
    printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n%s\n%s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.10.0.0/24\nEndpoint = %s:%s\nPersistentKeepalive = 5\n%s\n' \
        "$k0" "$PORT0" "$obfblock" "$fecblock" "$p1" "$UL1" "$PORT1" "$extra0" >"$out0"
    printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n%s\n%s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.10.0.0/24\nEndpoint = %s:%s\nPersistentKeepalive = 5\n%s\n' \
        "$k1" "$PORT1" "$obfblock" "$fecblock" "$p0" "$UL0" "$PORT0" "$extra1" >"$out1"
    return 0
}

bring_up_addrs() {
    ip -n "$NS0" addr add "$TUN0/24" dev "$IF0" || return 1
    ip -n "$NS1" addr add "$TUN1/24" dev "$IF1" || return 1
    ip -n "$NS0" link set "$IF0" mtu "$TUN_MTU" up || return 1
    ip -n "$NS1" link set "$IF1" mtu "$TUN_MTU" up || return 1
    return 0
}

apply_config() {
    local impl=$1 conf0=$2 conf1=$3 out rc0=0 rc1=0
    case "$impl" in
        kernel-amneziawg|go)
            out=$(awg_ns "$NS0" setconf "$IF0" "$conf0" 2>&1) || rc0=$?
            if [ "$rc0" != "0" ]; then
                echo "SETCONF_FAILED ns=$NS0 rc=$rc0 out=$out" >&2
                return 1
            fi
            out=$(awg_ns "$NS1" setconf "$IF1" "$conf1" 2>&1) || rc1=$?
            if [ "$rc1" != "0" ]; then
                echo "SETCONF_FAILED ns=$NS1 rc=$rc1 out=$out" >&2
                return 1
            fi
            ;;
        *)
            out=$(uwg_ns "$NS0" setconf "$IF0" "$conf0" 2>&1) || rc0=$?
            if [ "$rc0" != "0" ]; then
                echo "SETCONF_FAILED ns=$NS0 rc=$rc0 out=$out" >&2
                return 1
            fi
            out=$(uwg_ns "$NS1" setconf "$IF1" "$conf1" 2>&1) || rc1=$?
            if [ "$rc1" != "0" ]; then
                echo "SETCONF_FAILED ns=$NS1 rc=$rc1 out=$out" >&2
                return 1
            fi
            ;;
    esac
    return 0
}

apply_fec() {
    local impl=$1 fec=$2
    case "$impl" in
        kernel-umbrawg)
            if ! uwg_ns "$NS0" set "$IF0" fec "$fec" >/dev/null 2>&1; then
                echo "FEC_SET_FAILED ns=$NS0 fec=$fec" >&2
                return 1
            fi
            if ! uwg_ns "$NS1" set "$IF1" fec "$fec" >/dev/null 2>&1; then
                echo "FEC_SET_FAILED ns=$NS1 fec=$fec" >&2
                return 1
            fi
            ;;
    esac
    return 0
}

wait_tunnel() {
    local i
    for i in $(seq 1 40); do
        if ip netns exec "$NS0" ping -c 1 -W 1 "$TUN1" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

kernel_sample() {
    K_SLAB=$(awk '/^Slab:/ { print $2; exit }' /proc/meminfo)
    K_SUNRE=$(awk '/^SUnreclaim:/ { print $2; exit }' /proc/meminfo)
    K_MEMAVAIL=$(awk '/^MemAvailable:/ { print $2; exit }' /proc/meminfo)
    K_SLAB=${K_SLAB:-0}
    K_SUNRE=${K_SUNRE:-0}
    K_MEMAVAIL=${K_MEMAVAIL:-0}
}

slabinfo_snapshot() {
    local dest=$1
    if ! cat /proc/slabinfo >"$dest" 2>/dev/null; then
        : >"$dest"
    fi
}

kernel_meminfo_log() {
    local point=$1 impl=$2 fec=$3 peers=$4 obf=$5
    printf 'MEMINFO point=%s impl=%s fec=%s peers=%s obf=%s slab_kb=%s sunreclaim_kb=%s memavailable_kb=%s\n' \
        "$point" "$impl" "$fec" "$peers" "$obf" "$K_SLAB" "$K_SUNRE" "$K_MEMAVAIL" >>"$DIAG"
}

kernel_base_snapshot() {
    kernel_sample
    BASE_SLAB=$K_SLAB
    BASE_SUNRE=$K_SUNRE
    BASE_MEMAVAIL=$K_MEMAVAIL
    slabinfo_snapshot "$BASE_SLABFILE"
}

slab_diff() {
    local before=$1 after=$2 label=$3 tmp changed
    SLAB_CHANGED=0
    SLAB_TOP="-"
    if [ ! -s "$before" ] || [ ! -s "$after" ]; then
        printf 'SLAB_DIFF label=%s skipped=no_slabinfo\n' "$label" >>"$DIAG"
        return 0
    fi
    tmp=$(mktemp)
    awk 'FNR == 1 { file++ }
        $1 == "slabinfo" || $1 == "#" { next }
        file == 1 { active[$1] = $2; objsize[$1] = $4; next }
        ($1 in active) {
            d = $2 - active[$1]
            if (d != 0) {
                ad = d < 0 ? -d : d
                printf "%s %d %d %d %d %d\n", $1, active[$1], $2, d, ad, objsize[$1]
            }
        }' "$before" "$after" | sort -k5,5nr >"$tmp"
    changed=$(wc -l <"$tmp")
    SLAB_CHANGED=$changed
    if [ "$changed" -gt 0 ]; then
        SLAB_TOP=$(awk 'NR == 1 { sign = ($4 > 0) ? "+" : ""; printf "%s(%s%d objs)", $1, sign, $4 }' "$tmp")
        {
            printf 'SLAB_DIFF label=%s changed=%s\n' "$label" "$changed"
            head -20 "$tmp" | awk '{ printf "SLAB_DIFF_CACHE label=%s cache=%s active_before=%s active_after=%s delta_objs=%s objsize=%s\n", "'"$label"'", $1, $2, $3, $4, $6 }'
            awk '{ bytes += $4 * $6 } END { printf "SLAB_DIFF_BYTES label=%s approx_delta_kb=%d\n", "'"$label"'", bytes / 1024 }' "$tmp"
        } >>"$DIAG"
    else
        printf 'SLAB_DIFF label=%s changed=0\n' "$label" >>"$DIAG"
    fi
    rm -f "$tmp"
    return 0
}

kernel_row_metrics() {
    local load=$1
    kernel_sample
    ROW_SLAB_DELTA=$((K_SLAB - BASE_SLAB))
    ROW_PER_PEER=$(awk -v d="$ROW_SLAB_DELTA" -v p="$PEERS_CUR" 'BEGIN { printf "%.1f", d / p }')
    kernel_meminfo_log "row_$load" "$IMPL_CUR" "$FEC_CUR" "$PEERS_CUR" "$OBF_CUR"
    printf 'KERNEL_DELTA load=%s slab_delta_kb=%s sunreclaim_delta_kb=%s memavailable_delta_kb=%s per_peer_kb=%s\n' \
        "$load" "$ROW_SLAB_DELTA" "$((K_SUNRE - BASE_SUNRE))" "$((K_MEMAVAIL - BASE_MEMAVAIL))" "$ROW_PER_PEER" >>"$DIAG"
    slabinfo_snapshot "$ROW_SLABFILE"
    if [ "${SLAB_DIFF_DONE:-0}" = "0" ]; then
        slab_diff "$BASE_SLABFILE" "$ROW_SLABFILE" "$load"
        SLAB_DIFF_DONE=1
    fi
}

log_lsmod() {
    local impl=$1 mod line
    case "$impl" in
        kernel-umbrawg) mod=umbrawg ;;
        kernel-amneziawg) mod=amneziawg ;;
        *) return 0 ;;
    esac
    line=$(lsmod | awk -v m="$mod" '$1 == m { printf "size=%s refcnt=%s", $2, $3 }')
    [ -n "$line" ] || line="missing"
    printf 'LSMOD impl=%s mod=%s %s\n' "$impl" "$mod" "$line" >>"$DIAG"
    log "LSMOD impl=$impl mod=$mod $line"
}

sample_userspace() {
    US_RSS=()
    US_HWM=()
    US_PSS=()
    US_PD=()
    local pid rss hwm pss pd
    for pid in ${DAEMON_PIDS[@]+"${DAEMON_PIDS[@]}"}; do
        rss="-"
        hwm="-"
        pss="-"
        pd="-"
        if [ -r "/proc/$pid/status" ]; then
            rss=$(awk '$1 == "VmRSS:" { print $2; exit }' "/proc/$pid/status" 2>/dev/null || true)
            hwm=$(awk '$1 == "VmHWM:" { print $2; exit }' "/proc/$pid/status" 2>/dev/null || true)
            rss=${rss:--}
            hwm=${hwm:--}
        fi
        if [ -r "/proc/$pid/smaps_rollup" ]; then
            pss=$(awk '$1 == "Pss:" { print $2; exit }' "/proc/$pid/smaps_rollup" 2>/dev/null || true)
            pd=$(awk '$1 == "Private_Dirty:" { print $2; exit }' "/proc/$pid/smaps_rollup" 2>/dev/null || true)
            pss=${pss:--}
            pd=${pd:--}
        fi
        US_RSS+=("$rss")
        US_HWM+=("$hwm")
        US_PSS+=("$pss")
        US_PD+=("$pd")
        printf 'USERSPACE pid=%s rss_kb=%s hwm_kb=%s pss_kb=%s private_dirty_kb=%s impl=%s fec=%s peers=%s obf=%s\n' \
            "$pid" "$rss" "$hwm" "$pss" "$pd" "$IMPL_CUR" "$FEC_CUR" "$PEERS_CUR" "$OBF_CUR" >>"$DIAG"
    done
}

userspace_row_values() {
    local rss0 rss1 pss0 pss1
    rss0=${US_RSS[0]:--}
    rss1=${US_RSS[1]:--}
    pss0=${US_PSS[0]:--}
    pss1=${US_PSS[1]:--}
    ROW_RSS_SUM=""
    ROW_PSS=""
    ROW_RSS_PER="$rss0/$rss1"
    if is_uint "$rss0" && is_uint "$rss1"; then
        ROW_RSS_SUM=$((rss0 + rss1))
    fi
    if is_uint "$pss0" && is_uint "$pss1"; then
        ROW_PSS=$((pss0 + pss1))
    fi
}

live_mss() {
    local mtu mss
    mtu=$(ip netns exec "$NS0" ip -o link show "$IF0" 2>/dev/null |
        sed -n 's/.* mtu \([0-9][0-9]*\).*/\1/p' | head -1)
    [ -n "$mtu" ] || mtu=$TUN_MTU
    mss=$((mtu - 40))
    if [ "$mss" -gt 1420 ]; then
        mss=1420
    fi
    if [ "$mss" -lt 64 ]; then
        mss=64
    fi
    printf '%s' "$mss"
}

start_iperf_server() {
    local i
    if [ -f "$SRV_PIDFILE" ]; then
        kill "$(cat "$SRV_PIDFILE" 2>/dev/null)" 2>/dev/null || true
        rm -f "$SRV_PIDFILE"
    fi
    ip netns exec "$NS1" iperf3 -s -1 -D -p "$IPERF_PORT" --pidfile "$SRV_PIDFILE" --logfile "$SRV_LOG" || return 1
    for i in $(seq 1 50); do
        if ip netns exec "$NS1" ss -ltnH "sport = :$IPERF_PORT" 2>/dev/null | grep -q .; then
            SRV_PID=$(cat "$SRV_PIDFILE" 2>/dev/null || true)
            return 0
        fi
        sleep 0.1
    done
    return 1
}

stop_iperf_server() {
    if [ -n "${SRV_PID:-}" ]; then
        kill "$SRV_PID" 2>/dev/null || true
        SRV_PID=""
    fi
    rm -f "$SRV_PIDFILE"
    if [ -e "/var/run/netns/$NS1" ]; then
        ip netns exec "$NS1" pkill -x iperf3 2>/dev/null || true
    fi
}

load_tcp_and_sample() {
    local impl=$1 peers=$2 mss mid rc=0
    if ! start_iperf_server; then
        printf 'LOAD_FAILED reason=server impl=%s peers=%s fec=%s obf=%s\n' \
            "$impl" "$peers" "$FEC_CUR" "$OBF_CUR" >>"$DIAG"
        return 1
    fi
    mss=$(live_mss)
    mid=$((RUN / 2))
    if [ "$mid" -lt 1 ]; then
        mid=1
    fi
    ip netns exec "$NS0" iperf3 -c "$TUN1" -p "$IPERF_PORT" -t "$RUN" -P 1 -l "$mss" -J \
        >"$LOG_DIR/$CELL_TAG-tcp.json" 2>"$LOG_DIR/$CELL_TAG-tcp.err" &
    CLIENT_PID=$!
    sleep "$mid"
    if is_kernel_impl "$impl"; then
        kernel_row_metrics tcp
    else
        sample_userspace
        userspace_row_values
    fi
    wait "$CLIENT_PID" || rc=$?
    CLIENT_PID=""
    stop_iperf_server
    if [ "$rc" != "0" ]; then
        printf 'LOAD_FAILED reason=client rc=%s impl=%s peers=%s fec=%s obf=%s\n' \
            "$rc" "$impl" "$peers" "$FEC_CUR" "$OBF_CUR" >>"$DIAG"
        return 1
    fi
    return 0
}

setup_cell() {
    local impl=$1 fec=$2 obf=$3 peers=$4
    cleanup
    sleep 0.2
    setup_topology || return 1
    if is_kernel_impl "$impl"; then
        kernel_sample
        kernel_meminfo_log pre_module "$impl" "$fec" "$peers" "$obf"
        load_module "$impl" || return 1
        sleep 0.2
        kernel_base_snapshot
        kernel_meminfo_log base_pre_ifaces "$impl" "$fec" "$peers" "$obf"
        create_ifaces "$impl" || return 1
        sleep 0.2
        kernel_sample
        kernel_meminfo_log ifaces_only "$impl" "$fec" "$peers" "$obf"
    else
        start_impl "$impl" "$fec" || return 1
    fi
    bring_up_addrs || return 1
    CONF0=$(mktemp "${TMPDIR:-/tmp}/mem-conf0.XXXXXX")
    CONF1=$(mktemp "${TMPDIR:-/tmp}/mem-conf1.XXXXXX")
    make_configs "$impl" "$fec" "$obf" "$peers" "$CONF0" "$CONF1" || return 1
    apply_config "$impl" "$CONF0" "$CONF1" || return 1
    apply_fec "$impl" "$fec" || return 1
    wait_tunnel || return 1
    SLAB_DIFF_DONE=0
    sleep "$SETTLE"
    return 0
}

emit_row() {
    local impl=$1 fec=$2 peers=$3 load=$4 obf=$5 repeat=$6
    local rss_sum=$7 rss_per=$8 pss=$9 slab=${10} per_peer=${11}
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$impl" "$fec" "$peers" "$load" "$obf" "$repeat" \
        "$rss_sum" "$rss_per" "$pss" "$slab" "$per_peer" >>"$OUT"
}

print_summary() {
    [ -s "$OUT" ] || return 0
    python3 - "$OUT" <<'PY'
import csv
import statistics
import sys

path = sys.argv[1]
with open(path, newline="", encoding="utf-8") as handle:
    rows = list(csv.DictReader(handle))


def number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def median(values):
    numbers = [item for item in (number(value) for value in values) if item is not None]
    return statistics.median(numbers) if numbers else None


def show(value, digits=0):
    if value is None:
        return "-"
    return f"{value:.{digits}f}"


groups = {}
for row in rows:
    key = (row.get("impl", "?"), row.get("fec", "?"), row.get("peers", "?"),
           row.get("load", "?"), row.get("obf", "?"))
    groups.setdefault(key, []).append(row)

print("")
print(f"summary: rows={len(rows)} cells={len(groups)}")
print(f"{'impl':<17}{'fec':<10}{'peers':>5} {'load':<4}{'obf':>3}{'n':>3}"
      f"{'rss_kb':>10}{'pss_kb':>10}{'slab_kb':>10}{'per_peer':>10}")
for key in sorted(groups, key=lambda k: (k[0], k[1], int(k[2]), k[3], k[4])):
    group = groups[key]
    rss = median(row.get("rss_kb_sum") for row in group)
    pss = median(row.get("pss_kb") for row in group)
    slab = median(row.get("slab_delta_kb") for row in group)
    per_peer = median(row.get("per_peer_kb") for row in group)
    print(f"{key[0]:<17}{key[1]:<10}{key[2]:>5} {key[3]:<4}{key[4]:>3}{len(group):>3}"
          f"{show(rss):>10}{show(pss):>10}{show(slab):>10}{show(per_peer, 1):>10}")

empty = [row for row in rows
         if not row.get("rss_kb_sum") and not row.get("slab_delta_kb")]
if empty:
    print(f"empty rows: {len(empty)} (см. diag: LOAD_FAILED/SETUP_FAILED)")
print("note: userspace — RSS/PSS двух демонов; kernel — ΔSlab, per_peer = ΔSlab/peers")
print("detail: HWM/Private_Dirty и изменённые slab-кэши — в diag")
PY
}

require_tools
if command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCK"
    if ! flock -n 9; then
        echo "MEM_BUSY: flock $LOCK занят другим экземпляром (bench.sh или mem-matrix.sh)" >&2
        exit 1
    fi
fi
idle_guard
snapshot_state

mkdir -p "$BENCH_DIR/tmp" "$LOG_DIR" /var/run/umbrawg /var/run/amneziawg
: >"$DIAG"
printf '%s\n' "$RESULT_HEADER" >"$OUT"

HARNESS_STARTED=1
trap on_exit EXIT

log "start: $TOTAL_RUNS runs in $TOTAL_CELLS cells, csv=$OUT"
log "axes: impl={$IMPL_LIST} fec={$FEC_LIST} peers={$PEERS_LIST} load={$LOAD_LIST} obf={$OBF_LIST}"
log "env: REPEATS=$REPEATS SETTLE=${SETTLE}s RUN=${RUN}s underlay_mtu=$UNDERLAY_MTU tun_mtu=$TUN_MTU"
log "paths: uwg=$UWG daemon=$DAEMON go=$GO_BASELINE awg=$AWG ko=$MODDIR/umbrawg.ko obf=$OBF"

CELLS_DONE=0
RUNS_DONE=0
SECONDS=0

for IMPL_CUR in "${IMPLS[@]}"; do
    mapfile -t CELL_FECS < <(fec_values_for "$IMPL_CUR")
    for FEC_CUR in "${CELL_FECS[@]}"; do
        for OBF_CUR in "${OBFS[@]}"; do
            for PEERS_CUR in "${PEERS[@]}"; do
                CELLS_DONE=$((CELLS_DONE + 1))
                CELL_TAG=$(sanitize "mem-${RUN_ID}-${IMPL_CUR}-fec${FEC_CUR}-p${PEERS_CUR}-o${OBF_CUR}")
                BASE_SLABFILE="$LOG_DIR/$CELL_TAG-base.slabinfo"
                ROW_SLABFILE="$LOG_DIR/$CELL_TAG-row.slabinfo"
                log "[cell $CELLS_DONE/$TOTAL_CELLS] setup impl=$IMPL_CUR fec=$FEC_CUR peers=$PEERS_CUR obf=$OBF_CUR"
                if ! setup_cell "$IMPL_CUR" "$FEC_CUR" "$OBF_CUR" "$PEERS_CUR"; then
                    printf 'SETUP_FAILED impl=%s fec=%s peers=%s obf=%s\n' \
                        "$IMPL_CUR" "$FEC_CUR" "$PEERS_CUR" "$OBF_CUR" >>"$DIAG"
                    log "SETUP_FAILED impl=$IMPL_CUR fec=$FEC_CUR peers=$PEERS_CUR obf=$OBF_CUR (см. diag)"
                    continue
                fi
                if is_kernel_impl "$IMPL_CUR"; then
                    log_lsmod "$IMPL_CUR"
                fi
                SLAB_CHANGED=0
                SLAB_TOP="-"
                for repeat in $(seq 1 "$REPEATS"); do
                    for load in "${LOADS[@]}"; do
                        RUNS_DONE=$((RUNS_DONE + 1))
                        ROW_SLAB_DELTA=""
                        ROW_PER_PEER=""
                        ROW_RSS_SUM=""
                        ROW_RSS_PER=""
                        ROW_PSS=""
                        if [ "$load" = "tcp" ]; then
                            if ! load_tcp_and_sample "$IMPL_CUR" "$PEERS_CUR"; then
                                log "[run $RUNS_DONE/$TOTAL_RUNS] LOAD_FAILED impl=$IMPL_CUR fec=$FEC_CUR peers=$PEERS_CUR obf=$OBF_CUR"
                            fi
                        else
                            sleep "$SETTLE"
                            if is_kernel_impl "$IMPL_CUR"; then
                                kernel_row_metrics idle
                            else
                                sample_userspace
                                userspace_row_values
                            fi
                        fi
                        if is_kernel_impl "$IMPL_CUR"; then
                            emit_row "$IMPL_CUR" "$FEC_CUR" "$PEERS_CUR" "$load" "$OBF_CUR" "$repeat" \
                                "" "" "" "$ROW_SLAB_DELTA" "$ROW_PER_PEER"
                            log "[run $RUNS_DONE/$TOTAL_RUNS] impl=$IMPL_CUR fec=$FEC_CUR peers=$PEERS_CUR load=$load obf=$OBF_CUR rep=$repeat -> slab_delta_kb=${ROW_SLAB_DELTA:-?} per_peer_kb=${ROW_PER_PEER:-?} caches=${SLAB_CHANGED} top=${SLAB_TOP}"
                        else
                            emit_row "$IMPL_CUR" "$FEC_CUR" "$PEERS_CUR" "$load" "$OBF_CUR" "$repeat" \
                                "$ROW_RSS_SUM" "$ROW_RSS_PER" "$ROW_PSS" "" ""
                            log "[run $RUNS_DONE/$TOTAL_RUNS] impl=$IMPL_CUR fec=$FEC_CUR peers=$PEERS_CUR load=$load obf=$OBF_CUR rep=$repeat -> rss_kb_sum=${ROW_RSS_SUM:-?} per_proc=${ROW_RSS_PER:-?} pss_kb=${ROW_PSS:-?}"
                        fi
                    done
                done
            done
        done
    done
done

print_summary

log "done: $RUNS_DONE/$TOTAL_RUNS runs in ${SECONDS}s"
log "csv: $OUT"
log "diag: $DIAG"
log "logs: $LOG_DIR"
