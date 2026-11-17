#!/usr/bin/env bash
set -euo pipefail

umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

PEERS="${PEERS:-3}"
HUB_IFACE="${HUB_IFACE:-uwgH}"
PEER_IFACE_PREFIX="${PEER_IFACE_PREFIX:-uwgP}"
HUB_TUN="${HUB_TUN:-10.71.0.1}"
TUN_PREFIX="${TUN_PREFIX:-24}"
HUB_PORT="${HUB_PORT:-51820}"
PEER_PORT_BASE="${PEER_PORT_BASE:-51830}"
UNDERLAY_BASE="${UNDERLAY_BASE:-10.200}"
UNDERLAY_PREFIX="${UNDERLAY_PREFIX:-24}"
DURATION="${DURATION:-3}"
FILE_MIB="${FILE_MIB:-8}"
OBF="${OBF:-0}"
PARALLEL="${PARALLEL:-1}"
SCHED="${UMBRAWG_RX_SCHED:-peer}"
HANDSHAKE_TIMEOUT="${HANDSHAKE_TIMEOUT:-20}"

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

in_user_namespace() {
    [ "${UWB_DP_NAMESPACE:-0}" = "1" ]
}

enter_namespace() {
    in_user_namespace && return 0
    if command -v unshare >/dev/null 2>&1 && unshare -Urn true >/dev/null 2>&1; then
        exec unshare -Urn env UWB_DP_NAMESPACE=1 "$0" "$@"
    fi
    [ "$(id -u)" -eq 0 ] || skip "unshare -Urn недоступен, тест требует userns+netns"
}

case "$PEERS" in
    2 | 3 | 4) ;;
    *) fail "PEERS должен быть 2..4, получено $PEERS" ;;
esac

probe_veth() {
    ip link add uwgprobe0 type veth peer name uwgprobe1 >/dev/null 2>&1 || return 1
    ip link del uwgprobe0 >/dev/null 2>&1 || true
}

probe_tun() {
    local name="uwgprobe$$"
    [ -c /dev/net/tun ] || return 1
    ip tuntap add dev "$name" mode tun >/dev/null 2>&1 || return 1
    ip link del "$name" >/dev/null 2>&1 || true
}

enter_namespace

command -v ip >/dev/null 2>&1 || skip "нет ip (iproute2)"
command -v nsenter >/dev/null 2>&1 || skip "нет nsenter (util-linux)"
command -v sha256sum >/dev/null 2>&1 || skip "нет sha256sum"
command -v ping >/dev/null 2>&1 || skip "нет ping"

probe_veth || skip "veth недоступен (нет CAP_NET_ADMIN и userns запрещён)"
probe_tun || skip "TUN недоступен (нет /dev/net/tun или прав на него)"

UWG_BIN="$(resolve_uwg)" || skip "uwg не найден (задайте UWG)"
DAEMON_BIN="$(resolve_daemon)" || skip "демон umbrawg не найден (задайте DAEMON)"
[ -x "$UWG_BIN" ] || skip "uwg не исполняемый: $UWG_BIN"
[ -x "$DAEMON_BIN" ] || skip "демон не исполняемый: $DAEMON_BIN"

IPERF3=""
if command -v iperf3 >/dev/null 2>&1; then
    IPERF3="$(command -v iperf3)"
fi
NC=""
if command -v nc >/dev/null 2>&1; then
    NC="$(command -v nc)"
fi

RUNDIR="$(mktemp -d "${TMPDIR:-/tmp}/umbrawg-mp.XXXXXX")"
SUMMARY="$RUNDIR/summary.tsv"
: >"$SUMMARY"

HOLDER_PIDS=()
DAEMON_PIDS=()

cleanup() {
    local status=$?
    set +e
    local pid
    for pid in "${DAEMON_PIDS[@]:-}"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    for pid in "${DAEMON_PIDS[@]:-}"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done
    for pid in "${HOLDER_PIDS[@]:-}"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    if [ "${KEEP_ARTIFACTS:-0}" = "1" ]; then
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
    HOLDER_PIDS+=("$spawn")
    while [ "$SECONDS" -lt "$deadline" ]; do
        if [ -s "$pidfile" ]; then
            cat "$pidfile"
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

uwg_for() {
    local runtime=$1
    shift
    env UWG_RUNTIME_DIR="$runtime" NO_COLOR=1 "$UWG_BIN" "$@"
}

write_obf() {
    local obf=$1
    local header_key=$2
    if [ "$obf" = "1" ]; then
        cat <<EOF
Jc = 4
Jmin = 50
Jmax = 1000
S1 = 15
S2 = 30
S3 = 45
S4 = 60
H1 = 1000-1010
H2 = 2000-2010
H3 = 3000-3010
H4 = 4000-4010
I1 = <b 0x160d2f><c>
I2 = <r 32>
I3 = <t>
I4 = <rc 16>
I5 = <rd 8>
HeaderProtectionKey = $header_key
ContentPaddingAddition = 10-20
RandomTrailers = on
EOF
    fi
}

write_hub_config() {
    local path=$1
    local private=$2
    local header_key=$3
    local obf=$4
    {
        printf '[Interface]\n'
        printf 'PrivateKey = %s\n' "$private"
        printf 'ListenPort = %s\n' "$HUB_PORT"
        write_obf "$obf" "$header_key"
        local index
        for index in $(seq 1 "$PEERS"); do
            printf '\n[Peer]\n'
            printf 'PublicKey = %s\n' "${PEER_PUBLIC[$index]}"
            printf 'AllowedIPs = %s/32\n' "$(peer_tun "$index")"
            printf 'Endpoint = %s:%s\n' "$(peer_underlay "$index")" "$((PEER_PORT_BASE + index))"
            printf 'PersistentKeepalive = 1\n'
        done
    } >"$path"
}

write_peer_config() {
    local path=$1
    local index=$2
    local private=${PEER_PRIVATE[$index]}
    local header_key=$3
    local obf=$4
    {
        printf '[Interface]\n'
        printf 'PrivateKey = %s\n' "$private"
        printf 'ListenPort = %s\n' "$((PEER_PORT_BASE + index))"
        write_obf "$obf" "$header_key"
        printf '\n[Peer]\n'
        printf 'PublicKey = %s\n' "$HUB_PUBLIC"
        printf 'AllowedIPs = %s/32\n' "$HUB_TUN"
        printf 'Endpoint = %s:%s\n' "$(hub_underlay "$index")" "$HUB_PORT"
        printf 'PersistentKeepalive = 1\n'
    } >"$path"
}

peer_tun() {
    printf '%s.%s\n' "${HUB_TUN%.*}" "$(($1 + 1))"
}

hub_underlay() {
    printf '%s.%s.1\n' "$UNDERLAY_BASE" "$(($1 - 1))"
}

peer_underlay() {
    printf '%s.%s.2\n' "$UNDERLAY_BASE" "$(($1 - 1))"
}

peer_iface() {
    printf '%s%s\n' "$PEER_IFACE_PREFIX" "$1"
}

peer_dir() {
    printf '%s/peer-%s\n' "$RUNDIR" "$1"
}

hub_dir() {
    printf '%s/hub\n' "$RUNDIR"
}

start_daemons() {
    mkdir -p "$(hub_dir)"
    local index
    for index in $(seq 1 "$PEERS"); do
        mkdir -p "$(peer_dir "$index")"
    done

    ns "$HUB_PID" env \
        UWG_RUNTIME_DIR="$(hub_dir)" \
        UMBRAWG_RUNTIME_DIR="$(hub_dir)" \
        UMBRAWG_LOG_LEVEL="${UMBRAWG_LOG_LEVEL:-info}" \
        UMBRAWG_PARALLEL_RX="$PARALLEL" \
        UMBRAWG_RX_SCHED="$SCHED" \
        UMBRAWG_RX_STATS=1 \
        "$DAEMON_BIN" --foreground "$HUB_IFACE" >>"$RUNDIR/hub.log" 2>&1 &
    DAEMON_PIDS+=("$!")

    for index in $(seq 1 "$PEERS"); do
        ns "${PEER_PIDS[$index]}" env \
            UWG_RUNTIME_DIR="$(peer_dir "$index")" \
            UMBRAWG_RUNTIME_DIR="$(peer_dir "$index")" \
            UMBRAWG_LOG_LEVEL="${UMBRAWG_LOG_LEVEL:-info}" \
            UMBRAWG_PARALLEL_RX="$PARALLEL" \
            UMBRAWG_RX_SCHED="$SCHED" \
            UMBRAWG_RX_STATS=1 \
            "$DAEMON_BIN" --foreground "$(peer_iface "$index")" \
            >>"$RUNDIR/peer-$index.log" 2>&1 &
        DAEMON_PIDS+=("$!")
    done

    wait_until 15 socket_ready "$(hub_dir)" "$HUB_IFACE" \
        || fail "демон $HUB_IFACE не создал UAPI-сокет"
    for index in $(seq 1 "$PEERS"); do
        wait_until 15 socket_ready "$(peer_dir "$index")" "$(peer_iface "$index")" \
            || fail "демон $(peer_iface "$index") не создал UAPI-сокет"
    done
}

socket_ready() {
    local dir=$1
    local iface=$2
    [ -S "$dir/$iface.sock" ] || return 1
    local pid
    for pid in "${DAEMON_PIDS[@]}"; do
        kill -0 "$pid" 2>/dev/null || return 1
    done
    return 0
}

setup_links() {
    local index
    local hub_link
    local peer_link
    for index in $(seq 1 "$PEERS"); do
        hub_link="uwgvethH$index"
        peer_link="uwgvethP$index"
        ip link add "$hub_link" type veth peer name "$peer_link"
        ip link set "$hub_link" netns "$HUB_PID"
        ip link set "$peer_link" netns "${PEER_PIDS[$index]}"
        ns "$HUB_PID" ip link set "$hub_link" up
        ns "${PEER_PIDS[$index]}" ip link set "$peer_link" up
        ns "$HUB_PID" ip addr add "$(hub_underlay "$index")/$UNDERLAY_PREFIX" dev "$hub_link"
        ns "${PEER_PIDS[$index]}" ip addr add "$(peer_underlay "$index")/$UNDERLAY_PREFIX" \
            dev "$peer_link"
        ns "${PEER_PIDS[$index]}" ip link set lo up
    done
    ns "$HUB_PID" ip link set lo up
}

wait_handshakes() {
    local deadline=$((SECONDS + HANDSHAKE_TIMEOUT))
    local index
    local ready
    while [ "$SECONDS" -lt "$deadline" ]; do
        ready=1
        for index in $(seq 1 "$PEERS"); do
            local value
            value="$(uwg_for "$(hub_dir)" show "$HUB_IFACE" latest-handshakes 2>/dev/null |
                awk -v key="${PEER_PUBLIC[$index]}" '$1 == key {print $2}')"
            if [ -z "$value" ] || [ "${value:-0}" -eq 0 ]; then
                ready=0
            fi
        done
        if [ "$ready" = "1" ]; then
            return 0
        fi
        for index in $(seq 1 "$PEERS"); do
            ns "$HUB_PID" ping -c 1 -W 1 -q "$(peer_tun "$index")" >/dev/null 2>&1 || true
        done
        sleep 0.2
    done
    return 1
}

iperf_flow() {
    local index=$1
    local port=$((5300 + index))
    ns "$HUB_PID" "$IPERF3" -s -1 -p "$port" >"$RUNDIR/iperf-server-$index.log" 2>&1 &
    local server=$!
    sleep 0.4
    ns "${PEER_PIDS[$index]}" "$IPERF3" -c "$HUB_TUN" -p "$port" -t "$DURATION" -f m \
        >"$RUNDIR/iperf-client-$index.log" 2>&1 || true
    wait "$server" 2>/dev/null || true
}

flow_rate() {
    awk '
        /receiver/ {for (i = 1; i <= NF; i++) if ($i == "Mbits/sec" || $i == "Gbits/sec") rate = $(i - 1) " " $i}
        END {print (rate == "" ? "n/a" : rate)}' "$1"
}

flow_retr() {
    awk '
        /sender/ {if ($(NF - 1) ~ /^[0-9]+$/) retr = $(NF - 1)}
        END {print (retr == "" ? "n/a" : retr)}' "$1"
}

stream_file() {
    local index=$1
    local port=$((9100 + index))
    ns "$HUB_PID" "$NC" -l -p "$port" >"$RUNDIR/recv-$index.bin" 2>"$RUNDIR/nc-$index.err" &
    local server=$!
    sleep 0.4
    ns "${PEER_PIDS[$index]}" "$NC" -N -w 30 "$HUB_TUN" "$port" <"$RUNDIR/payload.bin"
    wait "$server" 2>/dev/null || true
}

run_measurements() {
    local index
    local cli_pids=()
    if [ -n "$IPERF3" ]; then
        for index in $(seq 1 "$PEERS"); do
            iperf_flow "$index" &
            cli_pids+=("$!")
        done
        local pid
        for pid in "${cli_pids[@]}"; do
            wait "$pid" 2>/dev/null || true
        done
    fi

    local total_mbit=0
    local retr_total=0
    local rate
    local retr
    local mbit
    for index in $(seq 1 "$PEERS"); do
        rate="n/a"
        retr="n/a"
        mbit=0
        if [ -n "$IPERF3" ]; then
            rate="$(flow_rate "$RUNDIR/iperf-client-$index.log")"
            retr="$(flow_retr "$RUNDIR/iperf-client-$index.log")"
            mbit="$(printf '%s\n' "$rate" | awk '{value = $1; if ($2 == "Gbits/sec") value *= 1000; printf "%.0f", value}')"
            total_mbit="$(awk -v a="$total_mbit" -v b="$mbit" 'BEGIN {printf "%.0f", a + b}')"
            if [ "$retr" != "n/a" ]; then
                retr_total=$((retr_total + retr))
            fi
        fi
        printf '%s\t%s\t%s\t%s\n' "$index" "$rate" "$retr" "$mbit" >>"$SUMMARY"
        log "пир $index: $rate, ретрансмиты $retr"
    done
    log "суммарно: $total_mbit Мбит/с, ретрансмиты $retr_total"

    if [ -n "$NC" ]; then
        for index in $(seq 1 "$PEERS"); do
            stream_file "$index"
            local src_sum
            local dst_sum
            src_sum="$(sha256sum "$RUNDIR/payload.bin" | awk '{print $1}')"
            dst_sum="$(sha256sum "$RUNDIR/recv-$index.bin" | awk '{print $1}')"
            if [ "$src_sum" != "$dst_sum" ]; then
                fail "пир $index: sha256 не совпадает"
            fi
            rm -f "$RUNDIR/recv-$index.bin"
        done
        log "файл ${FILE_MIB} MiB на каждого пира: sha256 совпал"
    fi
}

check_logs() {
    local log_file
    for log_file in "$RUNDIR"/hub.log "$RUNDIR"/peer-*.log; do
        if grep -Eq 'ERROR|panicked|worker stopped|parallel rx failure' "$log_file"; then
            printf -- '--- %s ---\n' "$log_file" >&2
            grep -En 'ERROR|panicked|worker stopped|parallel rx failure' "$log_file" >&2
            fail "в логе $log_file есть ошибки"
        fi
    done
}

log "uwg: $UWG_BIN"
log "демон: $DAEMON_BIN"
log "пиров: $PEERS, obf=$OBF, UMBRAWG_PARALLEL_RX=$PARALLEL, UMBRAWG_RX_SCHED=$SCHED"
log "iperf3: ${IPERF3:-нет}, nc: ${NC:-нет}"

HUB_PID="$(start_netns_holder hub)"
PEER_PIDS=()
for index in $(seq 1 "$PEERS"); do
    PEER_PIDS[$index]="$(start_netns_holder "peer-$index")"
done
log "netns: hub=$HUB_PID пиры=${PEER_PIDS[*]:1}"

setup_links
start_daemons

ns "$HUB_PID" ip link set "$HUB_IFACE" up
ns "$HUB_PID" ip addr add "$HUB_TUN/$TUN_PREFIX" dev "$HUB_IFACE"
for index in $(seq 1 "$PEERS"); do
    iface_name="$(peer_iface "$index")"
    ns "${PEER_PIDS[$index]}" ip link set "$iface_name" up
    ns "${PEER_PIDS[$index]}" ip addr add "$(peer_tun "$index")/$TUN_PREFIX" dev "$iface_name"
done

PEER_PRIVATE=()
PEER_PUBLIC=()
for index in $(seq 1 "$PEERS"); do
    PEER_PRIVATE[$index]="$(uwg_for "$RUNDIR" genkey)"
    PEER_PUBLIC[$index]="$(printf '%s\n' "${PEER_PRIVATE[$index]}" |
        uwg_for "$RUNDIR" pubkey)"
done
HUB_PRIVATE="$(uwg_for "$RUNDIR" genkey)"
HUB_PUBLIC="$(printf '%s\n' "$HUB_PRIVATE" | uwg_for "$RUNDIR" pubkey)"
HEADER_KEY="$(uwg_for "$RUNDIR" genkey)"

write_hub_config "$RUNDIR/hub.conf" "$HUB_PRIVATE" "$HEADER_KEY" "$OBF"
uwg_for "$(hub_dir)" setconf "$HUB_IFACE" "$RUNDIR/hub.conf" \
    || fail "setconf $HUB_IFACE"
for index in $(seq 1 "$PEERS"); do
    write_peer_config "$RUNDIR/peer-$index.conf" "$index" "$HEADER_KEY" "$OBF"
    uwg_for "$(peer_dir "$index")" setconf "$(peer_iface "$index")" \
        "$RUNDIR/peer-$index.conf" || fail "setconf $(peer_iface "$index")"
done

wait_handshakes || {
    for index in $(seq 1 "$PEERS"); do
        tail -20 "$RUNDIR/peer-$index.log" >&2 || true
    done
    tail -20 "$RUNDIR/hub.log" >&2 || true
    fail "рукопожатия не завершились за ${HANDSHAKE_TIMEOUT}s"
}
log "рукопожатия: ok"

for index in $(seq 1 "$PEERS"); do
    if ! ns "$HUB_PID" ping -c 2 -W 2 -q "$(peer_tun "$index")" >/dev/null 2>&1; then
        fail "ping до пира $index не прошёл"
    fi
done
log "ping: ok"

head -c "$((FILE_MIB * 1024 * 1024))" /dev/urandom >"$RUNDIR/payload.bin"

run_measurements
check_logs

log "--- rx stats (hub) ---"
grep 'rx stats' "$RUNDIR/hub.log" | tail -1 || true

log ""
log "прогон multi-peer: OK"
