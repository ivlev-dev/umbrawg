#!/usr/bin/env bash
set -euo pipefail

umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

IFACE_A="${IFACE_A:-uwgA}"
IFACE_B="${IFACE_B:-uwgB}"
UNDERLAY_A="${UNDERLAY_A:-10.200.0.1}"
UNDERLAY_B="${UNDERLAY_B:-10.200.0.2}"
UNDERLAY_PREFIX="${UNDERLAY_PREFIX:-24}"
PORT_A="${PORT_A:-51820}"
PORT_B="${PORT_B:-51821}"
TUN_A="${TUN_A:-10.71.0.1}"
TUN_B="${TUN_B:-10.71.0.2}"
TUN_PREFIX="${TUN_PREFIX:-24}"
UNDERLAY_MTU="${UNDERLAY_MTU:-1500}"
FILE_MIB="${FILE_MIB:-32}"
KEEP_ARTIFACTS="${KEEP_ARTIFACTS:-0}"
HANDSHAKE_TIMEOUT="${HANDSHAKE_TIMEOUT:-20}"
MIN_TCP_MBIT="${MIN_TCP_MBIT:-0}"

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

probe_netns() {
    unshare -n true >/dev/null 2>&1
}

enter_namespace

command -v ip >/dev/null 2>&1 || skip "нет ip (iproute2)"
command -v nsenter >/dev/null 2>&1 || skip "нет nsenter (util-linux)"
command -v sha256sum >/dev/null 2>&1 || skip "нет sha256sum"
command -v ping >/dev/null 2>&1 || skip "нет ping"

probe_veth || skip "veth недоступен (нет CAP_NET_ADMIN и userns запрещён)"
probe_tun || skip "TUN недоступен (нет /dev/net/tun или прав на него)"
probe_netns || skip "не удалось создать network namespace"

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

RUNDIR="$(mktemp -d "${TMPDIR:-/tmp}/umbrawg-dp.XXXXXX")"
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
    ip link del uwgveth0 >/dev/null 2>&1
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

start_daemons() {
    local parallel=$1
    local obf=$2
    local tag=$3
    DAEMON_A="$RUNDIR/$tag-a"
    DAEMON_B="$RUNDIR/$tag-b"
    mkdir -p "$DAEMON_A" "$DAEMON_B"
    : >"$RUNDIR/$tag-a.log"
    : >"$RUNDIR/$tag-b.log"

    ns "$PID_A" env \
        UWG_RUNTIME_DIR="$DAEMON_A" \
        UMBRAWG_RUNTIME_DIR="$DAEMON_A" \
        UMBRAWG_LOG_LEVEL="${UMBRAWG_LOG_LEVEL:-info}" \
        UMBRAWG_PARALLEL_RX="$parallel" \
        UMBRAWG_RX_SCHED="${UMBRAWG_RX_SCHED:-peer}" \
        UMBRAWG_RX_STATS="${UMBRAWG_RX_STATS:-1}" \
        UMBRAWG_UNDERLAY_MTU="$UNDERLAY_MTU" \
        "$DAEMON_BIN" --foreground "$IFACE_A" >>"$RUNDIR/$tag-a.log" 2>&1 &
    DAEMON_PID_A=$!
    ns "$PID_B" env \
        UWG_RUNTIME_DIR="$DAEMON_B" \
        UMBRAWG_RUNTIME_DIR="$DAEMON_B" \
        UMBRAWG_LOG_LEVEL="${UMBRAWG_LOG_LEVEL:-info}" \
        UMBRAWG_PARALLEL_RX="$parallel" \
        UMBRAWG_RX_SCHED="${UMBRAWG_RX_SCHED:-peer}" \
        UMBRAWG_RX_STATS="${UMBRAWG_RX_STATS:-1}" \
        UMBRAWG_UNDERLAY_MTU="$UNDERLAY_MTU" \
        "$DAEMON_BIN" --foreground "$IFACE_B" >>"$RUNDIR/$tag-b.log" 2>&1 &
    DAEMON_PID_B=$!

    if ! wait_until 15 socket_ready "$DAEMON_A" "$IFACE_A"; then
        printf -- '--- %s-a.log ---\n' "$tag" >&2
        cat "$RUNDIR/$tag-a.log" >&2 || true
        fail "$tag: демон $IFACE_A не создал UAPI-сокет"
    fi
    if ! wait_until 15 socket_ready "$DAEMON_B" "$IFACE_B"; then
        printf -- '--- %s-b.log ---\n' "$tag" >&2
        cat "$RUNDIR/$tag-b.log" >&2 || true
        fail "$tag: демон $IFACE_B не создал UAPI-сокет"
    fi
    if ! wait_until 10 interface_exists "$PID_A" "$IFACE_A"; then
        fail "$tag: интерфейс $IFACE_A не появился"
    fi
    if ! wait_until 10 interface_exists "$PID_B" "$IFACE_B"; then
        fail "$tag: интерфейс $IFACE_B не появился"
    fi

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
    local obf=$7
    local header_key=$8

    {
        printf '[Interface]\n'
        printf 'PrivateKey = %s\n' "$private"
        printf 'ListenPort = %s\n' "$port"
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
        printf '\n[Peer]\n'
        printf 'PublicKey = %s\n' "$peer_public"
        printf 'AllowedIPs = %s\n' "$allowed"
        printf 'Endpoint = %s\n' "$endpoint"
        printf 'PersistentKeepalive = 1\n'
    } >"$path"
}

uwg_for() {
    local runtime=$1
    shift
    env UWG_RUNTIME_DIR="$runtime" NO_COLOR=1 "$UWG_BIN" "$@"
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
    local deadline=$((SECONDS + HANDSHAKE_TIMEOUT))
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

ping_ok() {
    ns "$PID_A" ping -c 3 -W 2 -q "$TUN_B" >"$RUNDIR/ping.txt" 2>&1
}

transfer_file() {
    local src=$1
    local dst=$2
    local port=$3
    local attempt
    for attempt in 1 2 3; do
        rm -f "$dst"
        ns "$PID_B" "$NC" -l -p "$port" >"$dst" 2>"$RUNDIR/nc-server.err" &
        local server=$!
        sleep 0.4
        if ns "$PID_A" "$NC" -N -w 30 "$TUN_B" "$port" <"$src"; then
            wait "$server" 2>/dev/null || true
            if [ -s "$dst" ]; then
                return 0
            fi
        fi
        kill "$server" 2>/dev/null || true
        wait "$server" 2>/dev/null || true
        sleep 0.3
    done
    return 1
}

iperf_tcp() {
    local port=5201
    ns "$PID_B" "$IPERF3" -s -1 -p "$port" >"$RUNDIR/iperf-tcp-server.log" 2>&1 &
    local server=$!
    sleep 0.5
    ns "$PID_A" "$IPERF3" -c "$TUN_B" -p "$port" -t 3 -f m >"$RUNDIR/iperf-tcp.log" 2>&1 || true
    wait "$server" 2>/dev/null || true
    awk '
        /receiver/ {for (i = 1; i <= NF; i++) if ($i == "Mbits/sec" || $i == "Gbits/sec") rate = $(i - 1) " " $i}
        /sender/ {if ($(NF - 1) ~ /^[0-9]+$/) retr = $(NF - 1)}
        END {print (rate == "" ? "n/a" : rate) "|" (retr == "" ? "n/a" : retr)}' \
        "$RUNDIR/iperf-tcp.log"
}

iperf_udp() {
    local port=5202
    ns "$PID_B" "$IPERF3" -s -1 -p "$port" >"$RUNDIR/iperf-udp-server.log" 2>&1 &
    local server=$!
    sleep 0.5
    ns "$PID_A" "$IPERF3" -c "$TUN_B" -p "$port" -u -b 200M -t 2 -f m >"$RUNDIR/iperf-udp.log" 2>&1 || true
    wait "$server" 2>/dev/null || true
    awk '/receiver/ {for (i = 1; i <= NF; i++) if ($i == "Mbits/sec") value = $(i - 1); for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+\/[0-9]+$/) loss = $i " " $(i + 1)} END {print value " " loss}' \
        "$RUNDIR/iperf-udp.log"
}

stats_lines() {
    local log=$1
    grep -c 'rx stats' "$log" 2>/dev/null || true
}

wait_stats() {
    local log=$1
    local before=$2
    local timeout=$3
    local deadline=$((SECONDS + timeout))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if [ "$(stats_lines "$log")" -gt "$before" ]; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

drops_summary() {
    local log=$1
    local line
    line="$(grep -o 'drops([^)]*)' "$log" 2>/dev/null | tail -1)" || true
    if [ -z "$line" ]; then
        printf 'n/a\n'
        return 0
    fi
    printf '%s\n' "$line"
}

drops_compact() {
    local log=$1
    local line
    line="$(drops_summary "$log")"
    if [ "$line" = "n/a" ]; then
        printf 'n/a\n'
        return 0
    fi
    local parts
    parts="$(printf '%s\n' "$line" |
        sed 's/^drops(//; s/)$//' |
        tr ' ' '\n' |
        awk -F= '$2 != 0 {printf "%s=%s ", $1, $2}')"
    if [ -z "$parts" ]; then
        printf '0\n'
    else
        printf '%s\n' "${parts% }"
    fi
}

drops_field() {
    local log=$1
    local field=$2
    local line
    line="$(drops_summary "$log")"
    if [ "$line" = "n/a" ]; then
        printf 'n/a\n'
        return 0
    fi
    printf '%s\n' "$line" |
        sed 's/^drops(//; s/)$//' |
        tr ' ' '\n' |
        awk -F= -v field="$field" '$1 == field {print $2}'
}

stats_field() {
    local log=$1
    local field=$2
    grep -o "$field=[0-9]*" "$log" 2>/dev/null | tail -1 | cut -d= -f2
}

drops_unexpected() {
    local log=$1
    local allowed_field=${2:-}
    local line
    line="$(drops_summary "$log")"
    if [ "$line" = "n/a" ]; then
        printf 'n/a\n'
        return 0
    fi
    printf '%s\n' "$line" |
        sed 's/^drops(//; s/)$//' |
        tr ' ' '\n' |
        awk -F= -v allowed="$allowed_field" '
            BEGIN { count = split(allowed, names, " ") }
            $1 == "open" { next }
            {
                skip = 0
                for (i = 1; i <= count; i++) if ($1 == names[i]) skip = 1
                if (!skip && $2 != 0) printf "%s=%s ", $1, $2
            }
        '
}

check_logs() {
    local tag=$1
    local log
    for log in "$RUNDIR/$tag-a.log" "$RUNDIR/$tag-b.log"; do
        if grep -Eq 'ERROR|panicked|worker stopped|parallel rx failure' "$log"; then
            printf -- '--- %s ---\n' "$log" >&2
            grep -En 'ERROR|panicked|worker stopped|parallel rx failure' "$log" >&2
            fail "$tag: в логе $log есть ошибки"
        fi
    done
}

record() {
    local tag=$1
    local parallel=$2
    local obf=$3
    local hs=$4
    local tcp=$5
    local retr=$6
    local udp=$7
    local sha=$8
    local drops=$9
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$tag" "$parallel" "$obf" "$hs" "$tcp" "$retr" "$udp" "$sha" "$drops" >>"$SUMMARY"
}

run_case() {
    local tag=$1
    local parallel=$2
    local obf=$3
    log ""
    log "== прогон $tag: UMBRAWG_PARALLEL_RX=$parallel obf=$obf =="

    start_daemons "$parallel" "$obf" "$tag"
    local stats_before
    local stats_before_b
    stats_before="$(stats_lines "$RUNDIR/$tag-a.log")"
    stats_before_b="$(stats_lines "$RUNDIR/$tag-b.log")"

    write_config "$RUNDIR/$tag-a.conf" "$PRIVATE_A" "$PORT_A" "$PUBLIC_B" \
        "$TUN_B/32" "$UNDERLAY_B:$PORT_B" "$obf" "$HEADER_KEY"
    write_config "$RUNDIR/$tag-b.conf" "$PRIVATE_B" "$PORT_B" "$PUBLIC_A" \
        "$TUN_A/32" "$UNDERLAY_A:$PORT_A" "$obf" "$HEADER_KEY"

    uwg_for "$DAEMON_A" setconf "$IFACE_A" "$RUNDIR/$tag-a.conf" \
        || fail "$tag: setconf $IFACE_A"
    uwg_for "$DAEMON_B" setconf "$IFACE_B" "$RUNDIR/$tag-b.conf" \
        || fail "$tag: setconf $IFACE_B"

    local handshakes
    if ! handshakes="$(wait_handshake "$DAEMON_A" "$DAEMON_B")"; then
        printf -- '--- %s-a.log ---\n' "$tag" >&2
        tail -30 "$RUNDIR/$tag-a.log" >&2 || true
        printf -- '--- %s-b.log ---\n' "$tag" >&2
        tail -30 "$RUNDIR/$tag-b.log" >&2 || true
        fail "$tag: handshake не состоялся за ${HANDSHAKE_TIMEOUT}s"
    fi
    log "handshake: $handshakes"

    ping_ok || {
        cat "$RUNDIR/ping.txt" >&2 || true
        fail "$tag: ping $TUN_A -> $TUN_B не прошёл"
    }
    local ping_loss
    ping_loss="$(awk -F', ' '/packet loss/ {print $3}' "$RUNDIR/ping.txt" | sed 's/ packet loss//')"
    log "ping: потери $ping_loss"

    local tcp="skipped"
    local tcp_retr="skipped"
    local udp="skipped"
    if [ -n "$IPERF3" ]; then
        tcp="$(iperf_tcp)"
        tcp_retr="${tcp##*|}"
        tcp="${tcp%%|*}"
        log "iperf3 TCP: $tcp, ретрансмиты $tcp_retr"
        udp="$(iperf_udp)"
        log "iperf3 UDP: $udp"
        if [ -n "$MIN_TCP_MBIT" ] && [ "$MIN_TCP_MBIT" != "0" ]; then
            local tcp_mbit
            tcp_mbit="$(printf '%s\n' "$tcp" | awk '{print $1}')"
            if [ -n "$tcp_mbit" ] && awk -v value="$tcp_mbit" -v min="$MIN_TCP_MBIT" \
                'BEGIN {exit !(value < min)}'; then
                fail "$tag: TCP $tcp_mbit Mbit/s ниже порога $MIN_TCP_MBIT"
            fi
        fi
    else
        log "iperf3 не найден: пропуск замеров пропускной способности"
    fi

    local sha_result="skipped"
    if [ -n "$NC" ]; then
        local dst="$RUNDIR/$tag-dst.bin"
        transfer_file "$RUNDIR/payload.bin" "$dst" 9100 \
            || fail "$tag: передача файла через туннель не удалась"
        local src_sum
        local dst_sum
        src_sum="$(sha256sum "$RUNDIR/payload.bin" | awk '{print $1}')"
        dst_sum="$(sha256sum "$dst" | awk '{print $1}')"
        if [ "$src_sum" != "$dst_sum" ]; then
            fail "$tag: sha256 не совпадает ($src_sum != $dst_sum)"
        fi
        sha_result="$dst_sum"
        log "файл ${FILE_MIB} MiB: sha256 $sha_result совпал"
        rm -f "$dst"
    else
        log "nc не найден: пропуск проверки целостности"
    fi

    if [ "$parallel" = "1" ]; then
        wait_stats "$RUNDIR/$tag-a.log" "$stats_before" 7 || true
        wait_stats "$RUNDIR/$tag-b.log" "$stats_before_b" 7 || true
    fi
    check_logs "$tag"

    local drops="n/a"
    local drops_b="n/a"
    if [ "$parallel" = "1" ]; then
        drops="$(drops_summary "$RUNDIR/$tag-a.log")"
        drops_b="$(drops_summary "$RUNDIR/$tag-b.log")"
        if [ "$drops" = "n/a" ] || [ "$drops_b" = "n/a" ]; then
            fail "$tag: нет строк rx stats при UMBRAWG_RX_STATS=1"
        fi
        local allowed_a=""
        local allowed_b=""
        if [ "$obf" = "1" ]; then
            allowed_b="prepared"
        fi
        local queue_ok=1
        local side
        local queue
        local datagrams
        for side in "$RUNDIR/$tag-a.log" "$RUNDIR/$tag-b.log"; do
            queue="$(drops_field "$side" queue)"
            if [ "${queue:-0}" != "0" ]; then
                datagrams="$(stats_field "$side" datagrams)"
                if [ -z "$datagrams" ] || [ "${queue:-0}" -gt $((datagrams / 100)) ]; then
                    queue_ok=0
                fi
            fi
        done
        local allowed_extra=""
        if [ "$queue_ok" = "1" ]; then
            allowed_extra="queue"
        fi
        local unexpected_a
        local unexpected_b
        local permitted_a="$allowed_a"
        local permitted_b="$allowed_b"
        if [ -n "$allowed_extra" ]; then
            permitted_a="${permitted_a:+$permitted_a }$allowed_extra"
            permitted_b="${permitted_b:+$permitted_b }$allowed_extra"
        fi
        unexpected_a="$(drops_unexpected "$RUNDIR/$tag-a.log" "$permitted_a")"
        unexpected_b="$(drops_unexpected "$RUNDIR/$tag-b.log" "$permitted_b")"
        local prepared_a
        local prepared_b
        prepared_a="$(drops_field "$RUNDIR/$tag-a.log" prepared)"
        prepared_b="$(drops_field "$RUNDIR/$tag-b.log" prepared)"
        prepared_a="${prepared_a:-0}"
        prepared_b="${prepared_b:-0}"
        local limit=$((9 * (HANDSHAKE_TIMEOUT / 5 + 1)))
        if [ "$obf" = "1" ]; then
            if [ "$prepared_a" != "0" ]; then
                unexpected_a="$unexpected_a prepared=$prepared_a"
            fi
            if [ "$prepared_b" -gt "$limit" ]; then
                unexpected_b="$unexpected_b prepared=$prepared_b"
            fi
        fi
        if [ -n "$unexpected_a" ] || [ -n "$unexpected_b" ]; then
            printf -- '--- %s-a.log ---\n' "$tag" >&2
            printf 'дропы: %s\n' "$drops" >&2
            printf 'неожиданные: %s\n' "$unexpected_a" >&2
            printf -- '--- %s-b.log ---\n' "$tag" >&2
            printf 'дропы: %s\n' "$drops_b" >&2
            printf 'неожиданные: %s\n' "$unexpected_b" >&2
            fail "$tag: несогласованные дропы приёма"
        fi
        if [ "$obf" = "1" ] && [ "$prepared_b" != "0" ]; then
            log "счётчики дропов: $drops_b (prepared=$prepared_b — pre-handshake specials I1-I5 и Jc-джанк)"
        else
            log "счётчики дропов A: $drops"
            log "счётчики дропов B: $drops_b"
        fi
        local queue_a
        local queue_b
        queue_a="$(drops_field "$RUNDIR/$tag-a.log" queue)"
        queue_b="$(drops_field "$RUNDIR/$tag-b.log" queue)"
        if [ "${queue_a:-0}" != "0" ] || [ "${queue_b:-0}" != "0" ]; then
            log "queue-дропы объяснены переполнением приёмной очереди под нагрузкой (A=${queue_a}, B=${queue_b})"
        fi
    else
        log "счётчики дропов: rx stats выводится только в параллельном режиме"
    fi

    local compact="n/a"
    if [ "$parallel" = "1" ]; then
        compact="A:$(drops_compact "$RUNDIR/$tag-a.log") B:$(drops_compact "$RUNDIR/$tag-b.log")"
    fi
    record "$tag" "$parallel" "$obf" "$handshakes" "$tcp" "$tcp_retr" "$udp" "$sha_result" "$compact"

    stop_daemons
    rm -rf "$DAEMON_A" "$DAEMON_B"
    log "прогон $tag: OK"
}

log "uwg: $UWG_BIN"
log "демон: $DAEMON_BIN"
log "UMBRAWG_RX_SCHED: ${UMBRAWG_RX_SCHED:-peer}"
log "iperf3: ${IPERF3:-нет}"
log "nc: ${NC:-нет}"
log "файл для проверки целостности: ${FILE_MIB} MiB"
log "MTU подложки: ${UNDERLAY_MTU}"

ip link set lo up
start_netns_holder A
PID_A="$(cat "$RUNDIR/pid-A")"
start_netns_holder B
PID_B="$(cat "$RUNDIR/pid-B")"
log "netns: A=$PID_A B=$PID_B"

ip link add uwgveth0 type veth peer name uwgveth1
ip link set uwgveth0 netns "$PID_A"
ip link set uwgveth1 netns "$PID_B"
ns "$PID_A" ip link set uwgveth0 mtu "$UNDERLAY_MTU"
ns "$PID_B" ip link set uwgveth1 mtu "$UNDERLAY_MTU"
ns "$PID_A" ip link set uwgveth0 up
ns "$PID_B" ip link set uwgveth1 up
ns "$PID_A" ip addr add "$UNDERLAY_A/$UNDERLAY_PREFIX" dev uwgveth0
ns "$PID_B" ip addr add "$UNDERLAY_B/$UNDERLAY_PREFIX" dev uwgveth1
ns "$PID_A" ip link set lo up
ns "$PID_B" ip link set lo up

PRIVATE_A="$(uwg_for "$RUNDIR" genkey)"
PRIVATE_B="$(uwg_for "$RUNDIR" genkey)"
PUBLIC_A="$(printf '%s\n' "$PRIVATE_A" | uwg_for "$RUNDIR" pubkey)"
PUBLIC_B="$(printf '%s\n' "$PRIVATE_B" | uwg_for "$RUNDIR" pubkey)"
HEADER_KEY="$(uwg_for "$RUNDIR" genkey)"

head -c "$((FILE_MIB * 1024 * 1024))" /dev/urandom >"$RUNDIR/payload.bin"
log "payload sha256: $(sha256sum "$RUNDIR/payload.bin" | awk '{print $1}')"

if [ -n "${CASES:-}" ]; then
    :
elif [ "${UWB_DP_QUICK:-0}" = "1" ]; then
    CASES="obf1p0 obf1p1"
else
    CASES="obf1p0 obf1p1 obf0p0 obf0p1"
fi

for combo in $CASES; do
    case "$combo" in
        obf1p0) run_case "obf1-par0" 0 1 ;;
        obf1p1) run_case "obf1-par1" 1 1 ;;
        obf0p0) run_case "obf0-par0" 0 0 ;;
        obf0p1) run_case "obf0-par1" 1 0 ;;
        *) fail "неизвестный прогон: $case" ;;
    esac
done

printf '\n%-12s %-4s %-4s %-22s %-22s %-12s %-24s %s\n' \
    "прогон" "par" "obf" "handshake A/B" "iperf3 TCP" "ретрансмиты" "iperf3 UDP" "дропы"
while IFS=$'\t' read -r tag parallel obf hs tcp retr udp sha drops; do
    printf '%-12s %-4s %-4s %-22s %-22s %-12s %-24s %s\n' \
        "$tag" "$parallel" "$obf" "$hs" "$tcp" "$retr" "$udp" "$drops"
    printf '%-12s sha256 файла: %s\n' "" "$sha"
done <"$SUMMARY"

log ""
log "все прогоны завершены успешно"
