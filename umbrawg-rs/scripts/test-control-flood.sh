#!/usr/bin/env bash
set -euo pipefail

umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

IFACE_A="${IFACE_A:-uwgFA}"
IFACE_B="${IFACE_B:-uwgFB}"
UNDERLAY_A="${UNDERLAY_A:-10.201.0.1}"
UNDERLAY_B="${UNDERLAY_B:-10.201.0.2}"
UNDERLAY_PREFIX="${UNDERLAY_PREFIX:-24}"
PORT_A="${PORT_A:-51830}"
PORT_B="${PORT_B:-51831}"
TUN_A="${TUN_A:-10.72.0.1}"
TUN_B="${TUN_B:-10.72.0.2}"
TUN_PREFIX="${TUN_PREFIX:-24}"
FLOOD_PPS="${FLOOD_PPS:-5000}"
FLOOD_SECONDS="${FLOOD_SECONDS:-10}"
FLOOD_TCP_SECONDS="${FLOOD_TCP_SECONDS:-5}"
UNDER_LOAD_PPS="${UNDER_LOAD_PPS:-100}"
MIN_FLOOD_PERCENT="${MIN_FLOOD_PERCENT:-50}"
KEEP_ARTIFACTS="${KEEP_ARTIFACTS:-0}"

skip() {
    printf 'SKIP: %s\n' "$*" >&2
    exit 0
}

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

log() {
    printf '%s\n' "$*"
}

first_executable() {
    local candidate
    for candidate in "$@"; do
        if [ -n "$candidate" ] && [ -x "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

resolve_uwg() {
    if [ -n "${UWG:-}" ]; then
        printf '%s\n' "$UWG"
        return 0
    fi
    if first_executable \
        "$REPO_ROOT/../umbrawg-tools/target/release/uwg" \
        "$REPO_ROOT/../umbrawg-tools/target/debug/uwg" \
        "$REPO_ROOT/target/release/uwg" \
        "$REPO_ROOT/target/debug/uwg"; then
        return 0
    fi
    command -v uwg
}

resolve_daemon() {
    local candidate
    if [ -n "${DAEMON:-}" ]; then
        printf '%s\n' "$DAEMON"
        return 0
    fi
    if candidate="$(first_executable \
        "$REPO_ROOT/target/release/umbrawg" \
        "$REPO_ROOT/target/debug/umbrawg")"; then
        printf '%s\n' "$candidate"
        return 0
    fi
    command -v umbrawg
}

resolve_flood() {
    local candidate
    if [ -n "${FLOOD:-}" ]; then
        printf '%s\n' "$FLOOD"
        return 0
    fi
    if candidate="$(first_executable \
        "$REPO_ROOT/target/release/examples/initiation_flood" \
        "$REPO_ROOT/target/debug/examples/initiation_flood")"; then
        printf '%s\n' "$candidate"
        return 0
    fi
    command -v initiation_flood
}

in_user_namespace() {
    [ "${UWB_FLOOD_NAMESPACE:-0}" = "1" ]
}

enter_namespace() {
    in_user_namespace && return 0
    if command -v unshare >/dev/null 2>&1 && unshare -Urn true >/dev/null 2>&1; then
        exec unshare -Urn env UWB_FLOOD_NAMESPACE=1 "$0" "$@"
    fi
    [ "$(id -u)" -eq 0 ] || skip "unshare -Urn недоступен, тест требует userns+netns"
}

probe_veth() {
    ip link add uwgfp0 type veth peer name uwgfp1 >/dev/null 2>&1 || return 1
    ip link del uwgfp0 >/dev/null 2>&1 || true
}

probe_tun() {
    local name="uwgfp$$"
    [ -c /dev/net/tun ] || return 1
    ip tuntap add dev "$name" mode tun >/dev/null 2>&1 || return 1
    ip link del "$name" >/dev/null 2>&1 || true
}

probe_netns() {
    unshare -n true >/dev/null 2>&1
}

enter_namespace

command -v ip >/dev/null 2>&1 || skip "нет ip (iproute2)"
command -v nsenter >/dev/null 2>&1 || skip "нет nsenter (util-linux)"
command -v ping >/dev/null 2>&1 || skip "нет ping"
command -v iperf3 >/dev/null 2>&1 || skip "нет iperf3"
probe_veth || skip "veth недоступен (нет CAP_NET_ADMIN и userns запрещён)"
probe_tun || skip "TUN недоступен (нет /dev/net/tun или прав на него)"
probe_netns || skip "не удалось создать network namespace"

UWG_BIN="$(resolve_uwg)" || skip "uwg не найден (задайте UWG)"
DAEMON_BIN="$(resolve_daemon)" || skip "демон umbrawg не найден (задайте DAEMON)"
FLOOD_BIN="$(resolve_flood)" || skip "initiation_flood не найден (соберите пример или задайте FLOOD)"
[ -x "$UWG_BIN" ] || skip "uwg не исполняемый: $UWG_BIN"
[ -x "$DAEMON_BIN" ] || skip "демон не исполняемый: $DAEMON_BIN"
[ -x "$FLOOD_BIN" ] || skip "initiation_flood не исполняемый: $FLOOD_BIN"

RUNDIR="$(mktemp -d "${TMPDIR:-/tmp}/umbrawg-flood.XXXXXX")"
PID_A=""
PID_B=""
DAEMON_PID_A=""
DAEMON_PID_B=""
DAEMON_A=""
DAEMON_B=""
SUMMARY="$RUNDIR/summary.tsv"
: >"$SUMMARY"

cleanup() {
    local status=$?
    set +e
    stop_daemons
    for holder in "$PID_A" "$PID_B"; do
        if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then
            kill -TERM "$holder" 2>/dev/null
            wait "$holder" 2>/dev/null
        fi
    done
    ip link del uwgfveth0 >/dev/null 2>&1
    if [ "$KEEP_ARTIFACTS" = "1" ]; then
        printf 'артефакты прогона: %s\n' "$RUNDIR" >&2
    else
        rm -rf "$RUNDIR"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

start_netns_holder() {
    local tag=$1
    local pidfile="$RUNDIR/pid-$tag"
    unshare -n sh -c 'printf "%s\n" "$$" >"$1"; exec sleep 7200' sh "$pidfile" \
        >/dev/null 2>&1 &
    local spawn=$!
    local deadline=$((SECONDS + 10))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if [ -s "$pidfile" ]; then
            return 0
        fi
        sleep 0.05
    done
    kill "$spawn" 2>/dev/null || true
    fail "network namespace $tag не создан"
}

ns() {
    local pid=$1
    shift
    nsenter -t "$pid" -n "$@"
}

wait_until() {
    local timeout=$1
    shift
    local deadline=$((SECONDS + timeout))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if "$@"; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

interface_exists() {
    local pid=$1
    local name=$2
    ns "$pid" ip link show "$name" >/dev/null 2>&1
}

uwg_for() {
    local runtime=$1
    shift
    env UWG_RUNTIME_DIR="$runtime" NO_COLOR=1 "$UWG_BIN" "$@"
}

start_daemons() {
    local tag=$1
    local under_load=$2
    DAEMON_A="$RUNDIR/$tag-a"
    DAEMON_B="$RUNDIR/$tag-b"
    mkdir -p "$DAEMON_A" "$DAEMON_B"
    : >"$RUNDIR/$tag-a.log"
    : >"$RUNDIR/$tag-b.log"

    ns "$PID_A" env \
        UWG_RUNTIME_DIR="$DAEMON_A" \
        UMBRAWG_RUNTIME_DIR="$DAEMON_A" \
        UMBRAWG_LOG_LEVEL=info \
        UMBRAWG_PARALLEL_RX=1 \
        UMBRAWG_RX_SCHED=peer \
        UMBRAWG_RX_STATS=1 \
        UMBRAWG_UNDER_LOAD="$under_load" \
        UMBRAWG_UNDER_LOAD_PPS="$UNDER_LOAD_PPS" \
        "$DAEMON_BIN" --foreground "$IFACE_A" >>"$RUNDIR/$tag-a.log" 2>&1 &
    DAEMON_PID_A=$!
    ns "$PID_B" env \
        UWG_RUNTIME_DIR="$DAEMON_B" \
        UMBRAWG_RUNTIME_DIR="$DAEMON_B" \
        UMBRAWG_LOG_LEVEL=info \
        UMBRAWG_PARALLEL_RX=1 \
        UMBRAWG_RX_SCHED=peer \
        UMBRAWG_RX_STATS=1 \
        UMBRAWG_UNDER_LOAD="$under_load" \
        UMBRAWG_UNDER_LOAD_PPS="$UNDER_LOAD_PPS" \
        "$DAEMON_BIN" --foreground "$IFACE_B" >>"$RUNDIR/$tag-b.log" 2>&1 &
    DAEMON_PID_B=$!

    if ! wait_until 15 socket_ready "$DAEMON_A" "$IFACE_A"; then
        cat "$RUNDIR/$tag-a.log" >&2 || true
        fail "$tag: демон $IFACE_A не создал UAPI-сокет"
    fi
    if ! wait_until 15 socket_ready "$DAEMON_B" "$IFACE_B"; then
        cat "$RUNDIR/$tag-b.log" >&2 || true
        fail "$tag: демон $IFACE_B не создал UAPI-сокет"
    fi
    wait_until 10 interface_exists "$PID_A" "$IFACE_A" \
        || fail "$tag: интерфейс $IFACE_A не появился"
    wait_until 10 interface_exists "$PID_B" "$IFACE_B" \
        || fail "$tag: интерфейс $IFACE_B не появился"

    ns "$PID_A" ip link set "$IFACE_A" up
    ns "$PID_A" ip addr add "$TUN_A/$TUN_PREFIX" dev "$IFACE_A" 2>/dev/null || true
    ns "$PID_B" ip link set "$IFACE_B" up
    ns "$PID_B" ip addr add "$TUN_B/$TUN_PREFIX" dev "$IFACE_B" 2>/dev/null || true
}

socket_ready() {
    local dir=$1
    local iface=$2
    [ -S "$dir/$iface.sock" ] || return 1
    kill -0 "$DAEMON_PID_A" 2>/dev/null || return 1
    kill -0 "$DAEMON_PID_B" 2>/dev/null || return 1
    return 0
}

stop_daemons() {
    local pid
    for pid in "${DAEMON_PID_A:-}" "${DAEMON_PID_B:-}"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    for pid in "${DAEMON_PID_A:-}" "${DAEMON_PID_B:-}"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done
    DAEMON_PID_A=""
    DAEMON_PID_B=""
}

write_config() {
    local path=$1
    local private=$2
    local port=$3
    local peer_public=$4
    local allowed=$5
    local endpoint=$6
    {
        printf '[Interface]\n'
        printf 'PrivateKey = %s\n' "$private"
        printf 'ListenPort = %s\n' "$port"
        printf '\n[Peer]\n'
        printf 'PublicKey = %s\n' "$peer_public"
        printf 'AllowedIPs = %s\n' "$allowed"
        printf 'Endpoint = %s\n' "$endpoint"
        printf 'PersistentKeepalive = 1\n'
    } >"$path"
}

latest_handshake() {
    local runtime=$1
    local iface=$2
    uwg_for "$runtime" show "$iface" latest-handshakes 2>/dev/null \
        | awk 'NR == 1 {print $2}' || true
}

wait_handshake() {
    local runtime_a=$1
    local runtime_b=$2
    local deadline=$((SECONDS + 20))
    local hs_a=0
    local hs_b=0
    local attempt=0
    while [ "$SECONDS" -lt "$deadline" ]; do
        if [ $((attempt % 5)) -eq 0 ]; then
            ns "$PID_A" ping -c 1 -W 1 -q "$TUN_B" >/dev/null 2>&1 || true
        fi
        attempt=$((attempt + 1))
        hs_a="$(latest_handshake "$runtime_a" "$IFACE_A")"
        hs_b="$(latest_handshake "$runtime_b" "$IFACE_B")"
        if [ "${hs_a:-0}" -gt 0 ] && [ "${hs_b:-0}" -gt 0 ]; then
            printf '%s/%s\n' "$hs_a" "$hs_b"
            return 0
        fi
        sleep 0.2
    done
    return 1
}

iperf_tcp() {
    local seconds=$1
    local port=5301
    ns "$PID_B" iperf3 -s -1 -p "$port" >"$RUNDIR/iperf-server.log" 2>&1 &
    local server=$!
    sleep 0.5
    ns "$PID_A" iperf3 -c "$TUN_B" -p "$port" -t "$seconds" -f m \
        >"$RUNDIR/iperf-client.log" 2>&1 || true
    wait "$server" 2>/dev/null || true
    awk '
        /receiver/ {
            for (i = 1; i <= NF; i++) if ($i == "Mbits/sec" || $i == "Gbits/sec") rate = $(i - 1)
        }
        /sender/ {
            for (i = 1; i <= NF; i++) if ($i == "Mbits/sec" || $i == "Gbits/sec") sent = $(i - 1)
        }
        END {print (rate == "" ? "0" : rate) " " (sent == "" ? "0" : sent)}' \
        "$RUNDIR/iperf-client.log"
}

ping_loss() {
    ns "$PID_A" ping -c 5 -i 0.2 -W 1 -q "$TUN_B" >"$RUNDIR/ping.txt" 2>&1 || true
    awk -F', ' '/packet loss/ {print $3}' "$RUNDIR/ping.txt" | sed 's/ packet loss//'
}

stats_line() {
    local log=$1
    grep 'rx stats' "$log" 2>/dev/null | tail -1 || true
}

stats_field() {
    local line=$1
    local field=$2
    printf '%s\n' "$line" | grep -o "$field=[0-9]*" | tail -1 | cut -d= -f2
}

drops_field() {
    local line=$1
    local field=$2
    printf '%s\n' "$line" | grep -o 'drops([^)]*)' | tail -1 \
        | sed 's/^drops(//; s/)$//' | tr ' ' '\n' \
        | awk -F= -v field="$field" '$1 == field {print $2}'
}

check_logs() {
    local tag=$1
    local log
    for log in "$RUNDIR/$tag-a.log" "$RUNDIR/$tag-b.log"; do
        if grep -Eq 'ERROR|panicked|worker stopped|parallel rx failure|control thread stopped' "$log"; then
            printf -- '--- %s ---\n' "$log" >&2
            grep -En 'ERROR|panicked|worker stopped|parallel rx failure|control thread stopped' "$log" >&2
            fail "$tag: в логе $log есть ошибки"
        fi
    done
}

run_case() {
    local tag=$1
    local under_load=$2
    log ""
    log "== флуд: UMBRAWG_UNDER_LOAD=$under_load, порог ${UNDER_LOAD_PPS} инициаций/с, ${FLOOD_PPS} pps =="

    start_daemons "$tag" "$under_load"
    write_config "$RUNDIR/$tag-a.conf" "$PRIVATE_A" "$PORT_A" "$PUBLIC_B" \
        "$TUN_B/32" "$UNDERLAY_B:$PORT_B"
    write_config "$RUNDIR/$tag-b.conf" "$PRIVATE_B" "$PORT_B" "$PUBLIC_A" \
        "$TUN_A/32" "$UNDERLAY_A:$PORT_A"
    uwg_for "$DAEMON_A" setconf "$IFACE_A" "$RUNDIR/$tag-a.conf" \
        || fail "$tag: setconf $IFACE_A"
    uwg_for "$DAEMON_B" setconf "$IFACE_B" "$RUNDIR/$tag-b.conf" \
        || fail "$tag: setconf $IFACE_B"

    local handshakes
    if ! handshakes="$(wait_handshake "$DAEMON_A" "$DAEMON_B")"; then
        cat "$RUNDIR/$tag-a.log" >&2 || true
        cat "$RUNDIR/$tag-b.log" >&2 || true
        fail "$tag: handshake не состоялся"
    fi
    log "handshake: $handshakes"

    local baseline
    baseline="$(iperf_tcp 3)"
    local baseline_rx="${baseline##* }"
    log "TCP без флуда: ${baseline_rx} Mbit/s"
    local baseline_loss
    baseline_loss="$(ping_loss)"
    log "ping без флуда: потери ${baseline_loss}"

    local stats_before
    stats_before="$(grep -c 'rx stats' "$RUNDIR/$tag-b.log" || true)"
    local flood_log="$RUNDIR/$tag-flood.log"
    : >"$flood_log"
    ns "$PID_A" "$FLOOD_BIN" \
        --target "$UNDERLAY_B:$PORT_B" \
        --public-key "$PUBLIC_B" \
        --pps "$FLOOD_PPS" \
        --seconds "$FLOOD_SECONDS" >>"$flood_log" 2>&1 &
    local flood_pid=$!
    sleep 1
    local during
    during="$(iperf_tcp "$FLOOD_TCP_SECONDS")"
    local during_rx="${during##* }"
    local during_loss
    during_loss="$(ping_loss)"
    if ! wait "$flood_pid"; then
        cat "$flood_log" >&2 || true
        fail "$tag: флуд завершился ошибкой"
    fi
    log "флуд: $(tail -1 "$flood_log")"
    log "TCP во время флуда: ${during_rx} Mbit/s, ping: потери ${during_loss}"

    local deadline=$((SECONDS + 8))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if [ "$(grep -c 'rx stats' "$RUNDIR/$tag-b.log" || true)" -gt "$stats_before" ]; then
            break
        fi
        sleep 0.2
    done
    sleep 0.2
    local line
    line="$(stats_line "$RUNDIR/$tag-b.log")"
    [ -n "$line" ] || fail "$tag: нет rx stats"
    local control_drops
    control_drops="$(stats_field "$line" control_drops)"
    local queue_drops
    queue_drops="$(drops_field "$line" queue)"
    local open_drops
    open_drops="$(drops_field "$line" open)"
    local flood_stats
    flood_stats="$(grep 'rx stats' "$RUNDIR/$tag-b.log" | tail -6)"
    local saw_under_load=0
    if printf '%s\n' "$flood_stats" | grep -q 'under_load=1'; then
        saw_under_load=1
    fi
    log "счётчики: under_load=$saw_under_load control_drops=${control_drops:-0} queue=${queue_drops:-0} open=${open_drops:-0}"

    check_logs "$tag"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$under_load" "$baseline_rx" "$during_rx" "$baseline_loss" \
        "$during_loss" "$saw_under_load" "${control_drops:-0}" "${queue_drops:-0}" \
        >>"$SUMMARY"

    if awk -v baseline="$baseline_rx" -v during="$during_rx" -v min="$MIN_FLOOD_PERCENT" \
        'BEGIN {exit !(baseline > 0 && during < baseline * min / 100)}'; then
        fail "$tag: TCP во время флуда $during Mbit/s ниже ${MIN_FLOOD_PERCENT}% от $baseline Mbit/s"
    fi

    stop_daemons
    rm -rf "$DAEMON_A" "$DAEMON_B"
    log "прогон $tag: OK"
}

log "uwg: $UWG_BIN"
log "демон: $DAEMON_BIN"
log "флудер: $FLOOD_BIN"
log "флуд: ${FLOOD_PPS} инициаций/с, ${FLOOD_SECONDS}s; порог under-load ${UNDER_LOAD_PPS}/с"

ip link set lo up
start_netns_holder A
PID_A="$(cat "$RUNDIR/pid-A")"
start_netns_holder B
PID_B="$(cat "$RUNDIR/pid-B")"

ip link add uwgfveth0 type veth peer name uwgfveth1
ip link set uwgfveth0 netns "$PID_A"
ip link set uwgfveth1 netns "$PID_B"
ns "$PID_A" ip link set uwgfveth0 up
ns "$PID_B" ip link set uwgfveth1 up
ns "$PID_A" ip addr add "$UNDERLAY_A/$UNDERLAY_PREFIX" dev uwgfveth0
ns "$PID_B" ip addr add "$UNDERLAY_B/$UNDERLAY_PREFIX" dev uwgfveth1
ns "$PID_A" ip link set lo up
ns "$PID_B" ip link set lo up

PRIVATE_A="$(uwg_for "$RUNDIR" genkey)"
PRIVATE_B="$(uwg_for "$RUNDIR" genkey)"
PUBLIC_A="$(printf '%s\n' "$PRIVATE_A" | uwg_for "$RUNDIR" pubkey)"
PUBLIC_B="$(printf '%s\n' "$PRIVATE_B" | uwg_for "$RUNDIR" pubkey)"

run_case flood-protected 1
run_case flood-detector-off 0

log ""
printf '%-16s %-12s %-12s %-11s %-11s %-10s %-14s\n' \
    "режим" "TCP без" "TCP флуд" "потери без" "потери флуд" "under_load" "control/queue"
awk -F'\t' '{printf "%-16s %-12s %-12s %-11s %-11s %-10s %s/%s\n", ($1 == "1" ? "защита" : "без детектора"), $2, $3, $4, $5, $6, $7, $8}' "$SUMMARY"

while IFS=$'\t' read -r mode baseline during _loss_a _loss_b saw _cd _qd; do
    if [ "$mode" = "1" ] && [ "$saw" != "1" ]; then
        fail "детектор не включил under_load при флуде ${FLOOD_PPS} pps"
    fi
done <"$SUMMARY"

log "все прогоны завершены успешно"
