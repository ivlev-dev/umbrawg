#!/bin/bash
set -euo pipefail

BENCH_DIR=${BENCH_DIR:-$(cd "$(dirname "$0")" && pwd)}
REPO_ROOT=$(cd "$BENCH_DIR/.." && pwd)
WORKSPACE_ROOT=${WORKSPACE_ROOT:-$(cd "$REPO_ROOT/.." && pwd)}
. "$BENCH_DIR/bench-lib.sh"

RUSTDIR=${RUSTDIR:-$(first_existing_dir "$WORKSPACE_ROOT/umbrawg-rs" "$WORKSPACE_ROOT/rust")}
MODDIR=${MODDIR:-${MODULE_DIR:-$(first_existing_dir "$WORKSPACE_ROOT/umbrawg-linux-kernel-module/src" "$WORKSPACE_ROOT/module/src")}}
UWG=${UWG:-$(first_existing_file "$REPO_ROOT/target/release/uwg" "$WORKSPACE_ROOT/umbrawg-tools/target/release/uwg" "$WORKSPACE_ROOT/tools/target/release/uwg")}
DAEMON=${DAEMON:-$(first_existing_file "$RUSTDIR/target/release/umbrawg" "$RUSTDIR/umbrawg")}
GO_BASELINE=${GO_BASELINE:-$(first_existing_file /opt/baseline/amneziawg-go /usr/local/bin/amneziawg-go /usr/bin/amneziawg-go)}
OBF=${OBF:-$BENCH_DIR/obf-params.conf}
RESULT=${RESULT:-$BENCH_DIR/results.csv}
REPORT_PY=${REPORT_PY:-$BENCH_DIR/bench-report.py}
DIAG_USER=${DIAG:-}
UNDERLAY_MTU=${UNDERLAY_MTU:-9000}
GSO_SEGMENTS=${GSO_SEGMENTS:-}
RUST_RX_SCHED=${RUST_RX_SCHED:-peer}
RUST_PARALLEL=${RUST_PARALLEL:-0}
TUN_MTU=${TUN_MTU:-1420}
OVERHEAD_BASE=${OVERHEAD_BASE:-80}
SMOKE=${SMOKE:-0}
PLAN_ONLY=${PLAN_ONLY:-0}
DURATION=${DURATION:-3}
UDP_RATE=${UDP_RATE:-1G}
UDP_RATE_LIST=${UDP_RATE_LIST:-}
RUN_ID=${RUN_ID:-$(date +%Y%m%d-%H%M%S)}
FORCE=${FORCE:-0}
ALLOW_FRAGMENT=${ALLOW_FRAGMENT:-0}
IDLE_LOAD_MAX=${IDLE_LOAD_MAX:-1.0}
CPU_HOT_PCT=${CPU_HOT_PCT:-80}
VETH_QUEUES=${VETH_QUEUES:-$(nproc)}
VETH_RX_Q=${VETH_RX_Q:-$VETH_QUEUES}
VETH_TX_Q=${VETH_TX_Q:-$VETH_QUEUES}
RPS_MASK=${RPS_MASK:-off}
LOCK=${LOCK:-/tmp/uwg-bench.lock}

NS0=bn0
NS1=bn1
IF0=uwgb0
IF1=uwgb1
V0=bveth0
V1=bveth1
PORT0=51820
PORT1=51821
IPERF_CPU=${IPERF_CPU:-3}
IPERF_PORT=5201
TUNNEL_CPUS_1=${TUNNEL_CPUS_1:-0}
TUNNEL_CPUS_3=${TUNNEL_CPUS_3:-0-2}

if [ "$SMOKE" = "1" ]; then
    DEF_PEERS_LIST=1
    DEF_CONNS_LIST=1
    DEF_LOSS_LIST=0
    DEF_OBF_LIST=1
    DEF_IMPL_LIST="kernel-umbrawg kernel-amneziawg rust go"
    DEF_MODE_LIST=1c
    DEF_PROTO_LIST=tcp
    DEF_REPEATS=1
else
    DEF_PEERS_LIST="1 4"
    DEF_CONNS_LIST="1 10 100"
    DEF_LOSS_LIST=0
    DEF_OBF_LIST="0 1"
    DEF_IMPL_LIST="kernel-umbrawg kernel-amneziawg rust go"
    DEF_MODE_LIST="1c 3c"
    DEF_PROTO_LIST="tcp udp"
    DEF_REPEATS=3
fi

PEERS_LIST=${PEERS_LIST-$DEF_PEERS_LIST}
CONNS_LIST=${CONNS_LIST-$DEF_CONNS_LIST}
LOSS_LIST=${LOSS_LIST-$DEF_LOSS_LIST}
OBF_LIST=${OBF_LIST-$DEF_OBF_LIST}
if [ "$RUST_PARALLEL" = "1" ]; then
    DEF_IMPL_LIST="$DEF_IMPL_LIST rust-par"
fi
IMPL_LIST=${IMPL_LIST-$DEF_IMPL_LIST}
MODE_LIST=${MODE_LIST-$DEF_MODE_LIST}
PROTO_LIST=${PROTO_LIST-$DEF_PROTO_LIST}
REPEATS=${REPEATS:-$DEF_REPEATS}
if [ -z "$UDP_RATE_LIST" ]; then
    UDP_RATE_LIST=$UDP_RATE
fi

RESULT_HEADER="impl,mode,proto,conns,loss,obf,peers,mbit,extra,run,repeat,lost_percent,udp_rate,udp_mode,streams,frag,cpu_hot,cpu_total"

DAEMON_PIDS=()
WE_INSMOD_UMBRAWG=0
WE_MODPROBE_AMNEZIAWG=0
POSTFLIGHT_DONE=0
WORKQUEUE_CHANGED=0
MODS_AT_START=""
NETNS_AT_START=""
IPERF_AT_START=""

if command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCK"
    if ! flock -n 9; then
        echo "BENCH_BUSY: flock $LOCK занят другим экземпляром bench.sh" >&2
        exit 1
    fi
fi

cleanup() {
    set +e
    local p
    for p in ${DAEMON_PIDS[@]+"${DAEMON_PIDS[@]}"}; do
        kill "$p" 2>/dev/null
    done
    DAEMON_PIDS=()
    if [ -f /tmp/bench-srv.pid ]; then
        kill "$(cat /tmp/bench-srv.pid)" 2>/dev/null
        rm -f /tmp/bench-srv.pid
    fi
    if [ "$WE_INSMOD_UMBRAWG" = "1" ]; then
        rmmod umbrawg 2>/dev/null
        WE_INSMOD_UMBRAWG=0
    fi
    if [ "$WE_MODPROBE_AMNEZIAWG" = "1" ]; then
        rmmod amneziawg 2>/dev/null
        WE_MODPROBE_AMNEZIAWG=0
    fi
    ip netns del "$NS0" 2>/dev/null
    ip netns del "$NS1" 2>/dev/null
    rm -f "/var/run/umbrawg/$IF0.sock" "/var/run/umbrawg/$IF1.sock"
    rm -f "/var/run/amneziawg/$IF0.sock" "/var/run/amneziawg/$IF1.sock"
    if [ "$WORKQUEUE_CHANGED" = "1" ]; then
        echo "$(all_cpus_mask)" > /sys/devices/virtual/workqueue/cpumask 2>/dev/null
    fi
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

postflight() {
    local dirty=0 msg="" want cur mod ns pid
    [ "$POSTFLIGHT_DONE" = "1" ] && return 0
    POSTFLIGHT_DONE=1
    want=$(all_cpus_mask)
    cur=$(cat /sys/devices/virtual/workqueue/cpumask 2>/dev/null || echo "?")
    if [ "${HARNESS_STARTED:-0}" = "1" ] && [ "$WORKQUEUE_CHANGED" = "1" ] && [ "$cur" != "$want" ]; then
        dirty=1
        msg="$msg workqueue=$cur(want=$want)"
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

snapshot_state() {
    MODS_AT_START=$(lsmod | awk '$1 == "umbrawg" || $1 == "amneziawg" { print $1 }' | tr '\n' ' ' || true)
    NETNS_AT_START=$(ip netns list 2>/dev/null | awk '{ print $1 }' | tr '\n' ' ' || true)
    IPERF_AT_START=$(pgrep -x iperf3 2>/dev/null | tr '\n' ' ' || true)
}

trap on_exit EXIT

resolve_result() {
    local hdr="" target
    mkdir -p "$(dirname "$RESULT")"
    if [ -s "$RESULT" ]; then
        hdr=$(head -1 "$RESULT")
        if [ "$hdr" != "$RESULT_HEADER" ]; then
            target="${RESULT%.csv}-${RUN_ID}.csv"
            echo "RESULT_LEGACY: $RESULT имеет старую схему, пишу в $target" >&2
            RESULT=$target
        fi
    fi
    if [ -n "$DIAG_USER" ]; then
        DIAG=$DIAG_USER
    else
        DIAG=$RESULT.diag
    fi
}

init_result() {
    if [ ! -s "$RESULT" ]; then
        printf '%s\n' "$RESULT_HEADER" > "$RESULT"
    fi
    : >> "$DIAG"
}

mtu_guard() {
    local obf overhead verdict rc=0 max_overhead
    max_overhead=$OVERHEAD_BASE
    for obf in $OBF_LIST; do
        overhead=$(mtu_overhead "$OBF" "$obf" "$OVERHEAD_BASE")
        if [ "$overhead" -gt "$max_overhead" ]; then
            max_overhead=$overhead
        fi
    done
    verdict=$(mtu_verdict "$TUN_MTU" "$UNDERLAY_MTU" "$max_overhead") || rc=$?
    if [ "$rc" = "0" ]; then
        echo "MTU: $verdict"
        return 0
    fi
    echo "MTU_FRAGMENT_RISK: $verdict" >&2
    echo "MTU_FRAGMENT_RISK: $verdict" >> "$DIAG"
    if [ "$ALLOW_FRAGMENT" = "1" ]; then
        echo "MTU_FRAGMENT_RISK: продолжаю, ALLOW_FRAGMENT=1" >&2
        return 0
    fi
    echo "MTU_GUARD: задай TUN_MTU<=$((UNDERLAY_MTU - max_overhead)) (например TUN_MTU=1380) или UNDERLAY_MTU=9000, либо ALLOW_FRAGMENT=1" >&2
    exit 2
}

idle_guard() {
    local reasons
    if [ "$FORCE" = "1" ]; then
        echo "IDLE_GUARD: пропуск проверки, FORCE=1"
        return 0
    fi
    if reasons=$(bench_busy_reasons "$$"); then
        echo "IDLE_GUARD: стенд свободен"
        return 0
    fi
    echo "IDLE_GUARD: стенд занят, запуск отменён:" >&2
    printf '  %s\n' $reasons >&2
    echo "IDLE_GUARD: обойди через FORCE=1, если уверен, что замеры не пересекутся" >&2
    exit 3
}

require_tools() {
    local missing="" impl cmd
    [ -f "$OBF" ] || missing="$missing obf=$OBF"
    if [ -n "$IMPL_LIST" ]; then
        [ -x "$UWG" ] || missing="$missing uwg=$UWG"
        for cmd in ip iperf3 python3 ping; do
            command -v "$cmd" >/dev/null 2>&1 || missing="$missing cmd:$cmd"
        done
    fi
    for impl in $IMPL_LIST; do
        case "$impl" in
            kernel-umbrawg)
                [ -f "$MODDIR/umbrawg.ko" ] || missing="$missing kernel-umbrawg=$MODDIR/umbrawg.ko"
                ;;
            rust|rust-par)
                [ -x "$DAEMON" ] || missing="$missing rust=$DAEMON"
                ;;
            go)
                [ -x "$GO_BASELINE" ] || missing="$missing go=$GO_BASELINE"
                ;;
        esac
    done
    if [ -n "$missing" ]; then
        echo "REQUIRE_FAILED:$missing" >&2
        echo "REQUIRE_HINT: задай UWG, MODDIR (MODULE_DIR), DAEMON, GO_BASELINE, OBF; пути по умолчанию — см. bench/README.md" >&2
        exit 5
    fi
}

uwg_ns() {
    local ns=$1
    shift
    ip netns exec "$ns" "$UWG" "$@"
}

awg_ns() {
    local ns=$1
    shift
    ip netns exec "$ns" awg "$@"
}

setup_topology() {
    ip netns add "$NS0"
    ip netns add "$NS1"
    if ! ip link add "$V0" type veth peer name "$V1" numtxqueues "$VETH_TX_Q" numrxqueues "$VETH_RX_Q" 2>/dev/null; then
        echo "VETH_MULTIQUEUE_UNSUPPORTED: создаю veth без numtxqueues/numrxqueues" >> "$DIAG"
        ip link add "$V0" type veth peer name "$V1"
    fi
    ip link set "$V0" netns "$NS0"
    ip link set "$V1" netns "$NS1"
    ip -n "$NS0" link set "$V0" mtu "$UNDERLAY_MTU"
    ip -n "$NS1" link set "$V1" mtu "$UNDERLAY_MTU"
    ip -n "$NS0" addr add 192.168.77.1/24 dev "$V0"
    ip -n "$NS1" addr add 192.168.77.2/24 dev "$V1"
    ip -n "$NS0" link set "$V0" up
    ip -n "$NS1" link set "$V1" up
    ip -n "$NS0" link set lo up
    ip -n "$NS1" link set lo up
    if ! veth_enable_queues "$NS0" "$V0" "$VETH_RX_Q" "$VETH_TX_Q"; then
        echo "VETH_QUEUES_FAILED: $NS0/$V0 ethtool -L rx=$VETH_RX_Q tx=$VETH_TX_Q" >> "$DIAG"
    fi
    if ! veth_enable_queues "$NS1" "$V1" "$VETH_RX_Q" "$VETH_TX_Q"; then
        echo "VETH_QUEUES_FAILED: $NS1/$V1 ethtool -L rx=$VETH_RX_Q tx=$VETH_TX_Q" >> "$DIAG"
    fi
    if [ "$RPS_MASK" != "off" ]; then
        veth_set_rps "$NS0" "$V0" "$RPS_MASK"
        veth_set_rps "$NS1" "$V1" "$RPS_MASK"
    fi
    echo "QUEUES: $(veth_queue_report "$NS0" "$V0") | $(veth_queue_report "$NS1" "$V1")" >> "$DIAG"
}

set_loss() {
    local loss=$1
    ip netns exec "$NS0" tc qdisc del dev "$V0" root 2>/dev/null || true
    if [ "$loss" != "0" ]; then
        ip netns exec "$NS0" tc qdisc add dev "$V0" root netem loss "${loss}%"
    fi
}

make_configs() {
    local obf=$1
    local peers=$2
    local out0=$3
    local out1=$4
    local k0 k1 p0 p1 obfblock extra0 extra1 i cipherblock
    k0=$("$UWG" genkey)
    k1=$("$UWG" genkey)
    p0=$(printf '%s' "$k0" | "$UWG" pubkey)
    p1=$(printf '%s' "$k1" | "$UWG" pubkey)
    obfblock=""
    if [ "$obf" = "1" ]; then
        obfblock=$(obf_block_from_conf "$OBF" "$UWG" genkey)
    fi
    cipherblock=""
    if [ -n "${CIPHER:-}" ]; then
        cipherblock="Cipher = $CIPHER"
    fi
    extra0=""
    extra1=""
    i=2
    while [ "$i" -le "$peers" ]; do
        local pk0 pk1
        pk0=$(printf '%s' "$("$UWG" genkey)" | "$UWG" pubkey)
        pk1=$(printf '%s' "$("$UWG" genkey)" | "$UWG" pubkey)
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
    printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n%s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.9.0.0/24\nEndpoint = 192.168.77.2:%s\nPersistentKeepalive = 5\n%s\n%s\n' \
        "$k0" "$PORT0" "$obfblock" "$p1" "$PORT1" "$cipherblock" "$extra0" > "$out0"
    printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n%s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.9.0.0/24\nEndpoint = 192.168.77.1:%s\nPersistentKeepalive = 5\n%s\n%s\n' \
        "$k1" "$PORT1" "$obfblock" "$p0" "$PORT0" "$cipherblock" "$extra1" > "$out1"
}

bring_up_addrs() {
    ip -n "$NS0" addr add 10.9.0.1/24 dev "$IF0"
    ip -n "$NS1" addr add 10.9.0.2/24 dev "$IF1"
    ip -n "$NS0" link set "$IF0" mtu "$TUN_MTU" up
    ip -n "$NS1" link set "$IF1" mtu "$TUN_MTU" up
}

start_impl() {
    local impl=$1
    local mode=$2
    local threads=1
    local cpus rc=0
    if [ "$mode" = "3c" ]; then
        cpus=$TUNNEL_CPUS_3
        threads=3
    else
        cpus=$TUNNEL_CPUS_1
    fi
    case "$impl" in
        kernel-umbrawg)
            if lsmod | awk '$1 == "umbrawg" { found = 1 } END { exit !found }'; then
                echo "MODULE_ALREADY_LOADED: umbrawg уже загружен (чужой или старый модуль), insmod не выполняю" >&2
                return 1
            fi
            modprobe udp_tunnel || return 1
            modprobe ip6_udp_tunnel || return 1
            insmod "$MODDIR/umbrawg.ko" || return 1
            WE_INSMOD_UMBRAWG=1
            ip netns exec "$NS0" ip link add "$IF0" type umbrawg || return 1
            ip netns exec "$NS1" ip link add "$IF1" type umbrawg || return 1
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
            ip netns exec "$NS0" ip link add "$IF0" type amneziawg || return 1
            ip netns exec "$NS1" ip link add "$IF1" type amneziawg || return 1
            ;;
        rust|rust-par)
            if [ "$impl" = "rust-par" ]; then
                rx_env="UMBRAWG_PARALLEL_RX=1 UMBRAWG_RX_SCHED=$RUST_RX_SCHED"
            else
                rx_env="UMBRAWG_PARALLEL_RX=0"
            fi
            env $rx_env UMBRAWG_THREADS=$threads UMBRAWG_UNDERLAY_MTU=$UNDERLAY_MTU ${GSO_SEGMENTS:+UMBRAWG_GSO_SEGMENTS=$GSO_SEGMENTS} ip netns exec "$NS0" taskset -c "$cpus" "$DAEMON" --foreground "$IF0" >/tmp/bench-$IF0.log 2>&1 &
            DAEMON_PIDS+=($!)
            env $rx_env UMBRAWG_THREADS=$threads UMBRAWG_UNDERLAY_MTU=$UNDERLAY_MTU ${GSO_SEGMENTS:+UMBRAWG_GSO_SEGMENTS=$GSO_SEGMENTS} ip netns exec "$NS1" taskset -c "$cpus" "$DAEMON" --foreground "$IF1" >/tmp/bench-$IF1.log 2>&1 &
            DAEMON_PIDS+=($!)
            for _ in $(seq 1 50); do
                [ -S "/var/run/umbrawg/$IF0.sock" ] && [ -S "/var/run/umbrawg/$IF1.sock" ] && break
                sleep 0.1
            done
            [ -S "/var/run/umbrawg/$IF0.sock" ] && [ -S "/var/run/umbrawg/$IF1.sock" ] || return 1
            ;;
        go)
            GOMAXPROCS=$threads ip netns exec "$NS0" taskset -c "$cpus" "$GO_BASELINE" "$IF0" >/tmp/bench-$IF0.log 2>&1 &
            DAEMON_PIDS+=($!)
            GOMAXPROCS=$threads ip netns exec "$NS1" taskset -c "$cpus" "$GO_BASELINE" "$IF1" >/tmp/bench-$IF1.log 2>&1 &
            DAEMON_PIDS+=($!)
            for _ in $(seq 1 50); do
                [ -S "/var/run/amneziawg/$IF0.sock" ] && [ -S "/var/run/amneziawg/$IF1.sock" ] && break
                sleep 0.1
            done
            [ -S "/var/run/amneziawg/$IF0.sock" ] && [ -S "/var/run/amneziawg/$IF1.sock" ] || return 1
            ;;
        *)
            return 1
            ;;
    esac
    return "$rc"
}

apply_config() {
    local impl=$1
    local conf0=$2
    local conf1=$3
    local out rc0=0 rc1=0
    case "$impl" in
        kernel-amneziawg|go)
            out=$(awg_ns "$NS0" setconf "$IF0" "$conf0" 2>&1) || rc0=$?
            if [ "$rc0" != "0" ]; then echo "SETCONF_FAILED ns=$NS0 rc=$rc0 out=$out" >&2; return 1; fi
            out=$(awg_ns "$NS1" setconf "$IF1" "$conf1" 2>&1) || rc1=$?
            if [ "$rc1" != "0" ]; then echo "SETCONF_FAILED ns=$NS1 rc=$rc1 out=$out" >&2; return 1; fi
            ;;
        *)
            out=$(uwg_ns "$NS0" setconf "$IF0" "$conf0" 2>&1) || rc0=$?
            if [ "$rc0" != "0" ]; then echo "SETCONF_FAILED ns=$NS0 rc=$rc0 out=$out" >&2; return 1; fi
            out=$(uwg_ns "$NS1" setconf "$IF1" "$conf1" 2>&1) || rc1=$?
            if [ "$rc1" != "0" ]; then echo "SETCONF_FAILED ns=$NS1 rc=$rc1 out=$out" >&2; return 1; fi
            ;;
    esac
    return 0
}

wait_tunnel() {
    local i
    for i in $(seq 1 40); do
        if ip netns exec "$NS0" ping -c 1 -W 1 10.9.0.2 >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

start_iperf_server() {
    local i
    if [ -f /tmp/bench-srv.pid ]; then
        kill "$(cat /tmp/bench-srv.pid)" 2>/dev/null || true
        rm -f /tmp/bench-srv.pid
    fi
    ip netns exec "$NS1" taskset -c "$IPERF_CPU" iperf3 -s -1 -D --pidfile /tmp/bench-srv.pid --logfile /tmp/bench-srv.log
    for i in $(seq 1 50); do
        if ip netns exec "$NS1" ss -ltnH "sport = :$IPERF_PORT" 2>/dev/null | grep -q .; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

run_iperf() {
    local proto=$1
    local conns=$2
    local rate=$3
    local per_rate rate_bits
    if ! start_iperf_server; then
        echo "IPERF_SERVER_FAILED proto=$proto conns=$conns" >&2
        return 1
    fi
    if [ "$proto" = "tcp" ]; then
        if ! ip netns exec "$NS0" taskset -c "$IPERF_CPU" iperf3 -c 10.9.0.2 -p "$IPERF_PORT" -t "$DURATION" -P "$conns" -l 1420 -J > /tmp/bench-client.json; then
            echo "IPERF_FAILED proto=tcp conns=$conns" >&2
            return 1
        fi
    else
        if ! rate_bits=$(rate_bps "$rate"); then
            echo "RATE_INVALID rate=$rate" >&2
            return 1
        fi
        per_rate=$(udp_stream_rate "$rate_bits" "$conns")
        if ! ip netns exec "$NS0" taskset -c "$IPERF_CPU" iperf3 -c 10.9.0.2 -p "$IPERF_PORT" -t "$DURATION" -P "$conns" -u -b "$per_rate" -l 1340 -J > /tmp/bench-client.json; then
            echo "IPERF_FAILED proto=udp conns=$conns rate=$rate" >&2
            return 1
        fi
    fi
    python3 - "$proto" <<'PY'
import json
import sys

proto = sys.argv[1]
with open("/tmp/bench-client.json", "r", encoding="utf-8") as fh:
    data = json.load(fh)
end = data["end"]
received = end["sum_received"]
sent = end["sum_sent"]
mbit = round(float(received["bits_per_second"]) / 1e6, 1)
if proto == "tcp":
    retransmits = int(sent.get("retransmits", 0) or 0)
    print(f"{mbit} {retransmits} -")
else:
    lost = round(float(received.get("lost_percent", 0.0) or 0.0), 3)
    print(f"{mbit} {lost} {lost}")
PY
}

emit_row() {
    local impl=$1 mode=$2 proto=$3 conns=$4 loss=$5 obf=$6 peers=$7
    local mbit=$8 extra=$9 lost=${10} rate=${11} rm=${12} streams=${13} repeat=${14} frag=${15}
    local cpu_hot=${16} cpu_total=${17}
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$impl" "$mode" "$proto" "$conns" "$loss" "$obf" "$peers" "$mbit" "$extra" \
        "$RUN_ID" "$repeat" "$lost" "$rate" "$rm" "$streams" "$frag" \
        "$cpu_hot" "$cpu_total" >> "$RESULT"
}

run_report() {
    if [ ! -f "$REPORT_PY" ]; then
        echo "REPORT_SKIPPED: нет $REPORT_PY" >&2
        return 0
    fi
    if ! python3 "$REPORT_PY" "$RESULT" --md "$RESULT.md" --agg "$RESULT.agg.csv"; then
        echo "REPORT_FAILED: $RESULT" >&2
        return 0
    fi
    echo "REPORT_MD=$RESULT.md"
    echo "REPORT_AGG=$RESULT.agg.csv"
}

resolve_result
snapshot_state
mtu_guard
idle_guard
HARNESS_STARTED=1
init_result

echo "RUN_ID=$RUN_ID"
echo "RESULT=$RESULT"
echo "DIAG=$DIAG"
echo "PATHS bench_dir=$BENCH_DIR uwg=$UWG moddir=$MODDIR rustdir=$RUSTDIR daemon=$DAEMON go_baseline=$GO_BASELINE obf=$OBF"
echo "PLAN impls=[$IMPL_LIST] modes=[$MODE_LIST] protos=[$PROTO_LIST] conns=[$CONNS_LIST] obf=[$OBF_LIST] peers=[$PEERS_LIST] repeats=$REPEATS cpu_hot_pct=$CPU_HOT_PCT iperf_cpu=$IPERF_CPU tunnel_cpus_1=$TUNNEL_CPUS_1 tunnel_cpus_3=$TUNNEL_CPUS_3"
echo "ENV UMBRAWG_UNDERLAY_MTU=$UNDERLAY_MTU UMBRAWG_GSO_SEGMENTS=${GSO_SEGMENTS:-} RUST_PARALLEL=$RUST_PARALLEL RUST_RX_SCHED=$RUST_RX_SCHED"

if [ "$PLAN_ONLY" = "1" ]; then
    echo "PLAN_ONLY: прогоны не запускаются"
    run_report
    echo "RESULTS=$RESULT"
    echo "DIAG=$DIAG"
    exit 0
fi

require_tools
mkdir -p /var/run/umbrawg

for impl in $IMPL_LIST; do
    for mode in $MODE_LIST; do
        if [ "$mode" = "1c" ]; then
            cpus=$TUNNEL_CPUS_1
        else
            cpus=$TUNNEL_CPUS_3
        fi
        if [ "$impl" = "kernel-umbrawg" ] || [ "$impl" = "kernel-amneziawg" ]; then
            echo "$(cpu_mask "$cpus")" > /sys/devices/virtual/workqueue/cpumask 2>/dev/null || true
            WORKQUEUE_CHANGED=1
        fi
        for obf in $OBF_LIST; do
            for peers in $PEERS_LIST; do
                cleanup
                sleep 0.3
                if ! setup_topology; then
                    echo "TOPOLOGY_FAILED impl=$impl mode=$mode obf=$obf peers=$peers" | tee -a "$DIAG" >&2
                    continue
                fi
                if ! start_impl "$impl" "$mode"; then
                    echo "START_FAILED impl=$impl mode=$mode obf=$obf peers=$peers" | tee -a "$DIAG" >&2
                    tail -5 "/tmp/bench-$IF1.log" 2>/dev/null | tee -a "$DIAG" || true
                    continue
                fi
                bring_up_addrs
                conf0=$(mktemp)
                conf1=$(mktemp)
                make_configs "$obf" "$peers" "$conf0" "$conf1"
                if ! apply_config "$impl" "$conf0" "$conf1"; then
                    echo "APPLY_FAILED impl=$impl mode=$mode obf=$obf peers=$peers" | tee -a "$DIAG" >&2
                    tail -5 "/tmp/bench-$IF1.log" 2>/dev/null | tee -a "$DIAG" || true
                    rm -f "$conf0" "$conf1"
                    continue
                fi
                if ! wait_tunnel; then
                    echo "TUNNEL_FAILED impl=$impl mode=$mode obf=$obf peers=$peers" | tee -a "$DIAG" >&2
                    tail -5 "/tmp/bench-$IF1.log" 2>/dev/null | tee -a "$DIAG" || true
                    rm -f "$conf0" "$conf1"
                    continue
                fi
                for loss in $LOSS_LIST; do
                    set_loss "$loss"
                    for proto in $PROTO_LIST; do
                        if [ "$proto" = "udp" ]; then
                            rates=$UDP_RATE_LIST
                        else
                            rates="-"
                        fi
                        for rate in $rates; do
                            if [ "$proto" = "udp" ] && [ "$rate" = "0" ]; then
                                udp_mode=unlimited
                            elif [ "$proto" = "udp" ]; then
                                udp_mode=fixed
                            else
                                udp_mode=-
                            fi
                            for conns in $CONNS_LIST; do
                                if [ "$conns" -le 1 ]; then
                                    streams=single
                                else
                                    streams=multi
                                fi
                                for repeat in $(seq 1 "$REPEATS"); do
                                    frag_before=$(( $(frag_total "$NS0") + $(frag_total "$NS1") ))
                                    cpu_snap_before=$(mktemp)
                                    proc_stat_snapshot "$cpu_snap_before" || true
                                    if ! out=$(run_iperf "$proto" "$conns" "$rate"); then
                                        rm -f "$cpu_snap_before"
                                        echo "IPERF_FAILED impl=$impl mode=$mode proto=$proto conns=$conns rate=$rate obf=$obf" | tee -a "$DIAG" >&2
                                        emit_row "$impl" "$mode" "$proto" "$conns" "$loss" "$obf" "$peers" FAIL 0 - "$rate" "$udp_mode" "$streams" "$repeat" -1 - -
                                        continue
                                    fi
                                    cpu_snap_after=$(mktemp)
                                    proc_stat_snapshot "$cpu_snap_after" || true
                                    cpu_line=$(cpu_busy_summary "$cpu_snap_before" "$cpu_snap_after" "$CPU_HOT_PCT" || true)
                                    rm -f "$cpu_snap_before" "$cpu_snap_after"
                                    cpu_hot=-
                                    cpu_total=-
                                    if [ -n "$cpu_line" ]; then
                                        cpu_hot=$(printf '%s' "$cpu_line" | sed -n 's/.*hot_cpus=\([0-9][0-9]*\).*/\1/p')
                                        cpu_total=$(printf '%s' "$cpu_line" | sed -n 's/.*total=\([0-9][0-9]*\).*/\1/p')
                                        [ -n "$cpu_hot" ] || cpu_hot=-
                                        [ -n "$cpu_total" ] || cpu_total=-
                                        printf 'CPU_BUSY impl=%s mode=%s proto=%s conns=%s obf=%s run=%s %s iperf_cpu=%s tunnel_cpus=%s\n' \
                                            "$impl" "$mode" "$proto" "$conns" "$obf" "$repeat" "$cpu_line" "$IPERF_CPU" "$cpus" >> "$DIAG"
                                    fi
                                    frag_after=$(( $(frag_total "$NS0") + $(frag_total "$NS1") ))
                                    frag=$((frag_after - frag_before))
                                    mbit=$(echo "$out" | awk '{print $1}')
                                    extra=$(echo "$out" | awk '{print $2}')
                                    lost=$(echo "$out" | awk '{print $3}')
                                    emit_row "$impl" "$mode" "$proto" "$conns" "$loss" "$obf" "$peers" "$mbit" "$extra" "$lost" "$rate" "$udp_mode" "$streams" "$repeat" "$frag" "$cpu_hot" "$cpu_total"
                                    if [ "$frag" -gt 0 ]; then
                                        echo "FRAGMENTED impl=$impl mode=$mode proto=$proto conns=$conns rate=$rate new_frag=$frag" | tee -a "$DIAG" >&2
                                    fi
                                    echo "$impl $mode $proto c=$conns rate=$rate loss=$loss obf=$obf peers=$peers rep=$repeat -> $mbit Mbit/s (extra=$extra) cpu_hot=$cpu_hot cpu_total=$cpu_total"
                                done
                            done
                        done
                    done
                done
                rm -f "$conf0" "$conf1"
            done
        done
    done
done

run_report
echo "RESULTS=$RESULT"
echo "DIAG=$DIAG"
