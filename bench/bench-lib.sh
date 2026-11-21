#!/bin/bash

first_existing_dir() {
    local p
    for p in "$@"; do
        if [ -d "$p" ]; then
            printf '%s' "$p"
            return 0
        fi
    done
    printf '%s' ""
}

first_existing_file() {
    local p
    for p in "$@"; do
        if [ -f "$p" ]; then
            printf '%s' "$p"
            return 0
        fi
    done
    printf '%s' ""
}

cpu_mask() {
    local list=$1 mask=0 b i s e
    for b in ${list//,/ }; do
        if [[ "$b" == *-* ]]; then
            s=${b%-*}
            e=${b#*-}
            for ((i = s; i <= e; i++)); do
                mask=$((mask | (1 << i)))
            done
        else
            mask=$((mask | (1 << b)))
        fi
    done
    printf '%x' "$mask"
}

all_cpus_mask() {
    cpu_mask "0-$(( $(nproc) - 1 ))"
}

snmp_frag_counts_file() {
    local path=$1
    awk '/^Ip:/ {
        if (hdr == 0) {
            for (i = 2; i <= NF; i++) idx[$i] = i
            hdr = 1
            next
        }
        printf "%s %s %s\n", $(idx["FragOKs"]), $(idx["FragFails"]), $(idx["FragCreates"])
    }' "$path"
}

snmp_frag_counts() {
    local ns=$1
    if [ -n "$ns" ]; then
        ip netns exec "$ns" cat /proc/net/snmp | snmp_frag_counts_file /dev/stdin
    else
        snmp_frag_counts_file /proc/net/snmp
    fi
}

frag_total() {
    local ns=$1 ok fails creates
    read -r ok fails creates < <(snmp_frag_counts "$ns")
    [ -n "${ok:-}" ] || ok=0
    [ -n "${creates:-}" ] || creates=0
    printf '%s' $((ok + creates))
}

obf_s4() {
    local conf=$1 val
    val=""
    if [ -f "$conf" ]; then
        val=$(grep -E '^[[:space:]]*S4[[:space:]]*=' "$conf" | head -1 | sed -E 's/^[^=]*=[[:space:]]*([0-9]+).*$/\1/' || true)
    fi
    [ -n "$val" ] || val=0
    printf '%s' "$val"
}

mtu_overhead() {
    local conf=$1 obf=$2 base=${3:-80} s4=0
    if [ "$obf" = "1" ] && [ -n "$conf" ] && [ -f "$conf" ]; then
        s4=$(obf_s4 "$conf")
    fi
    printf '%s' $((base + s4))
}

mtu_verdict() {
    local tun=$1 underlay=$2 overhead=$3 limit
    if [ "$underlay" -ge 9000 ]; then
        printf 'ok underlay=%s tun=%s overhead=%s\n' "$underlay" "$tun" "$overhead"
        return 0
    fi
    limit=$((underlay - overhead))
    if [ "$tun" -le "$limit" ]; then
        printf 'ok underlay=%s tun=%s overhead=%s limit=%s\n' "$underlay" "$tun" "$overhead" "$limit"
        return 0
    fi
    printf 'fragment underlay=%s tun=%s overhead=%s limit=%s\n' "$underlay" "$tun" "$overhead" "$limit"
    return 1
}

rate_bps() {
    local r=$1 num mul suf
    case "$r" in
        *[kK]) mul=1000; num=${r%?} ;;
        *[mM]) mul=1000000; num=${r%?} ;;
        *[gG]) mul=1000000000; num=${r%?} ;;
        *) mul=1; num=$r ;;
    esac
    case "$num" in
        ""|*[!0-9.]*|*.*.*) return 1 ;;
    esac
    awk -v n="$num" -v m="$mul" 'BEGIN { printf "%d", n * m }'
}

udp_stream_rate() {
    local total=$1 conns=$2 per
    if [ "$total" = "0" ]; then
        printf '0'
        return 0
    fi
    if [ "$conns" -le 1 ]; then
        printf '%s' "$total"
        return 0
    fi
    per=$((total / conns))
    if [ "$per" -lt 1000 ]; then
        per=1000
    fi
    printf '%s' "$per"
}

veth_rx_queue_count() {
    local ns="" dev
    if [ $# -ge 2 ]; then ns=$1; dev=$2; else dev=${1:-}; fi
    local n
    if [ -n "$ns" ]; then
        n=$(ip netns exec "$ns" sh -c 'ls -d /sys/class/net/"$1"/queues/rx-* 2>/dev/null | wc -l' sh "$dev" || true)
    else
        n=$(ls -d "/sys/class/net/$dev/queues"/rx-* 2>/dev/null | wc -l || true)
    fi
    printf '%s' "${n:-0}"
}

veth_tx_queue_count() {
    local ns="" dev
    if [ $# -ge 2 ]; then ns=$1; dev=$2; else dev=${1:-}; fi
    local n
    if [ -n "$ns" ]; then
        n=$(ip netns exec "$ns" sh -c 'ls -d /sys/class/net/"$1"/queues/tx-* 2>/dev/null | wc -l' sh "$dev" || true)
    else
        n=$(ls -d "/sys/class/net/$dev/queues"/tx-* 2>/dev/null | wc -l || true)
    fi
    printf '%s' "${n:-0}"
}

veth_enable_queues() {
    local ns=$1 dev=$2 rx=$3 tx=$4
    if [ "$rx" -le 1 ] && [ "$tx" -le 1 ]; then
        return 0
    fi
    ip netns exec "$ns" ethtool -L "$dev" rx "$rx" tx "$tx" >/dev/null 2>&1
}

veth_queue_report() {
    local ns="" dev
    if [ $# -ge 2 ]; then ns=$1; dev=$2; else dev=${1:-}; fi
    if [ -n "$ns" ]; then
        ip netns exec "$ns" sh -c '
            dev=$1
            rxq=$(ls -d /sys/class/net/"$dev"/queues/rx-* 2>/dev/null | wc -l)
            txq=$(ls -d /sys/class/net/"$dev"/queues/tx-* 2>/dev/null | wc -l)
            rps=$(cat /sys/class/net/"$dev"/queues/rx-*/rps_cpus 2>/dev/null | tr "\n" "," )
            xps=$(cat /sys/class/net/"$dev"/queues/tx-*/xps_cpus 2>/dev/null | tr "\n" "," )
            printf "dev=%s rxq=%s txq=%s rps=%s xps=%s" "$dev" "${rxq:-0}" "${txq:-0}" "${rps:-none}" "${xps:-none}"
        ' sh "$dev"
        return 0
    fi
    local f rps="" xps=""
    for f in /sys/class/net/"$dev"/queues/rx-*/rps_cpus; do
        [ -f "$f" ] || continue
        rps="$rps${rps:+,}$(cat "$f" 2>/dev/null)"
    done
    for f in /sys/class/net/"$dev"/queues/tx-*/xps_cpus; do
        [ -f "$f" ] || continue
        xps="$xps${xps:+,}$(cat "$f" 2>/dev/null)"
    done
    [ -n "$rps" ] || rps="none"
    [ -n "$xps" ] || xps="none"
    printf 'dev=%s rxq=%s txq=%s rps=%s xps=%s' \
        "$dev" "$(veth_rx_queue_count "$dev")" "$(veth_tx_queue_count "$dev")" "$rps" "$xps"
}

veth_set_rps() {
    local ns="" dev mask=""
    if [ $# -ge 3 ]; then ns=$1; dev=$2; mask=$3; else dev=$1; mask=$2; fi
    if [ -n "$ns" ]; then
        ip netns exec "$ns" sh -c '
            dev=$1
            mask=$2
            for f in /sys/class/net/"$dev"/queues/rx-*/rps_cpus; do
                [ -f "$f" ] || continue
                printf "%s" "$mask" > "$f" 2>/dev/null || true
            done
        ' sh "$dev" "$mask"
        return 0
    fi
    local f
    for f in /sys/class/net/"$dev"/queues/rx-*/rps_cpus; do
        [ -f "$f" ] || continue
        printf '%s' "$mask" > "$f" 2>/dev/null || true
    done
}

proc_stat_cpu_lines() {
    local path=${1:-/proc/stat}
    awk '$1 ~ /^cpu[0-9]+$/ { print }' "$path"
}

proc_stat_snapshot() {
    local dest=$1 src=${2:-/proc/stat}
    proc_stat_cpu_lines "$src" > "$dest"
}

cpu_busy_summary() {
    local before=$1 after=$2 hot_pct=${3:-80}
    awk -v hot="$hot_pct" '
        FNR == 1 { fileidx++ }
        fileidx == 1 {
            if ($1 ~ /^cpu[0-9]+$/) {
                t = 0
                for (i = 2; i <= 9; i++) t += $i
                prev_total[$1] = t
                prev_idle[$1] = $5 + $6
            }
            next
        }
        $1 ~ /^cpu[0-9]+$/ {
            if (!($1 in prev_total)) next
            t = 0
            for (i = 2; i <= 9; i++) t += $i
            dt = t - prev_total[$1]
            di = ($5 + $6) - prev_idle[$1]
            busy = (dt > 0) ? (dt - di) * 100.0 / dt : 0
            if (busy < 0) busy = 0
            b = int(busy + 0.5)
            per = per (per == "" ? "" : ",") b
            if (b >= hot) hot_count++
            busy_time += busy * dt / 100.0
            total_time += dt
            seen = 1
        }
        END {
            if (!seen) {
                printf "per_cpu=- hot_cpus=0 total=0"
                exit 0
            }
            total = (total_time > 0) ? int(busy_time * 100.0 / total_time + 0.5) : 0
            printf "per_cpu=%s hot_cpus=%d total=%d", per, hot_count, total
        }
    ' "$before" "$after"
}

bench_busy_reasons() {
    local self_pid=$1 reasons=() l1 mods nets p
    l1=$(awk '{print $1}' /proc/loadavg)
    if awk -v l="$l1" -v m="$IDLE_LOAD_MAX" 'BEGIN { exit !(l > m) }'; then
        reasons+=("load1=$l1>$IDLE_LOAD_MAX")
    fi
    if pgrep -x iperf3 >/dev/null 2>&1; then
        reasons+=("iperf3=$(pgrep -x iperf3 | tr '\n' ',' | sed 's/,$//' || true)")
    fi
    mods=$(lsmod | awk '$1 == "umbrawg" || $1 == "amneziawg" { print $1 }' | tr '\n' ',' | sed 's/,$//')
    if [ -n "$mods" ]; then
        reasons+=("modules=$mods")
    fi
    nets=$(ip netns list 2>/dev/null | awk '$1 == "bn0" || $1 == "bn1" { print $1 }' | tr '\n' ',' | sed 's/,$//')
    if [ -n "$nets" ]; then
        reasons+=("netns=$nets")
    fi
    for p in $(pgrep -f "bench/bench.sh" 2>/dev/null); do
        if [ "$p" != "$self_pid" ]; then
            reasons+=("bench.sh=$p")
        fi
    done
    if [ "${#reasons[@]}" -eq 0 ]; then
        return 0
    fi
    printf '%s\n' "${reasons[@]}"
    return 1
}

obf_block_from_conf() {
    local conf=$1
    shift
    local hp line key
    [ -f "$conf" ] || return 0
    hp=$("$@") || return 1
    if [ -z "$hp" ]; then
        echo "obf_block_from_conf: не удалось сгенерировать HeaderProtectionKey" >&2
        return 1
    fi
    while IFS= read -r line; do
        line=${line#"${line%%[![:space:]]*}"}
        case "$line" in
            ""|\#*|\[*\]) continue ;;
        esac
        key=${line%%=*}
        key=${key//[[:space:]]/}
        case "$key" in
            PrivateKey|ListenPort|PublicKey|AllowedIPs|Endpoint|PersistentKeepalive) continue ;;
            HeaderProtectionKey) printf 'HeaderProtectionKey = %s\n' "$hp"; continue ;;
        esac
        printf '%s\n' "$line"
    done < "$conf"
}
