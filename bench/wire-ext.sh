#!/bin/bash
set -uo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

pick_bin() {
    local candidate
    for candidate in "$@"; do
        if [ -x "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

KO=${KO:-$ROOT/umbrawg-linux-kernel-module/src/umbrawg.ko}
if [ -z "${UWG:-}" ]; then
    UWG=$(pick_bin "$ROOT/umbrawg-tools/target/release/uwg" "$ROOT/umbrawg-tools/target/debug/uwg") \
        || UWG=$ROOT/umbrawg-tools/target/release/uwg
fi
if [ -z "${RUST:-}" ]; then
    RUST=$(pick_bin "$ROOT/umbrawg-rs/target/release/umbrawg" "$ROOT/umbrawg-rs/target/debug/umbrawg") \
        || RUST=$ROOT/umbrawg-rs/target/release/umbrawg
fi

IMPL=${IMPL:-rust}
DIR=${DIR:-k0}
KFEC=${KFEC:-${FEC:-adaptive}}
RFEC=${RFEC:-${FEC:-$KFEC}}
NETEM_LOSS=${NETEM_LOSS:-0}
NETEM_DELAY=${NETEM_DELAY:-0}
NETEM_RATE=${NETEM_RATE:-}
NETEM_BOTH=${NETEM_BOTH:-1}
UMTU=${UMTU:-${UNDERLAY_MTU:-9000}}
TUNMTU=${TUNMTU:-${TUN_MTU:-1420}}
DUR=${DUR:-4}
TAG=${TAG:-ext}
SKIP_PING=${SKIP_PING:-0}
KEEP=${KEEP:-0}
UDP_RATE=${UDP_RATE:-400M}
FEC_SHARD=${FEC_SHARD:-}
ACK_INTERVAL=${ACK_INTERVAL:-}
UMBRAWG_THREADS=${UMBRAWG_THREADS:-}

PORT0=${PORT0:-53920}
PORT1=${PORT1:-53921}
IPERF_PORT=${IPERF_PORT:-5291}
OUT=${OUT:-/tmp/wire-ext-$TAG}

NS0=xwg0
NS1=xwg1
V0=xwgv0
V1=xwgv1
UL0=192.168.77.1
UL1=192.168.77.2
TUN0=10.9.0.1
TUN1=10.9.0.2

CAP_PID=""
SRV_PID=""
DPID=""
DPID2=""
CONF0=""
CONF1=""
READY=0

log() { printf '[%s] %s\n' "$TAG" "$*"; }
die() { printf '[%s] FATAL: %s\n' "$TAG" "$*" >&2; exit 1; }

validate_fec() {
    case "$1" in
        off|adaptive) return 0 ;;
        [0-9]*:[0-9]*) return 0 ;;
        *) return 1 ;;
    esac
}

remove_namespaces() {
    local ns pid
    for ns in "$NS0" "$NS1"; do
        [ -e "/var/run/netns/$ns" ] || continue
        for pid in $(ip netns pids "$ns" 2>/dev/null); do
            kill "$pid" 2>/dev/null
        done
        sleep 0.1
        ip netns del "$ns" 2>/dev/null
    done
    ip link del "$V0" 2>/dev/null
    ip link del "$V1" 2>/dev/null
}

cleanup() {
    set +u
    if [ -n "${CAP_PID:-}" ]; then
        kill "$CAP_PID" 2>/dev/null
        wait "$CAP_PID" 2>/dev/null
    fi
    if [ -n "${SRV_PID:-}" ]; then
        kill "$SRV_PID" 2>/dev/null
    fi
    if [ -n "${ONS:-}" ] && [ -e "/var/run/netns/$ONS" ]; then
        ip netns exec "$ONS" pkill -x iperf3 2>/dev/null
    fi
    if [ "${KEEP:-0}" = "1" ]; then
        log "KEEP=1: netns $NS0/$NS1, module/daemons and logs are left in place"
        log "inspect: ip netns exec $NS0 bash | ip netns exec $NS1 bash"
        if [ "${IMPL:-}" = "rust2" ]; then
            log "cleanup: ip netns pids $NS0 $NS1 | xargs -r kill; ip netns del $NS0; ip netns del $NS1"
        else
            log "cleanup: ip netns del $NS0; ip netns del $NS1; rmmod umbrawg"
        fi
        return 0
    fi
    if [ -n "${DPID:-}" ]; then
        kill "$DPID" 2>/dev/null
    fi
    if [ -n "${DPID2:-}" ]; then
        kill "$DPID2" 2>/dev/null
        wait "$DPID2" 2>/dev/null
    fi
    remove_namespaces
    rm -f /var/run/umbrawg/uwg0.sock /var/run/umbrawg/uwg1.sock
    [ -n "${CONF0:-}" ] && rm -f "$CONF0"
    [ -n "${CONF1:-}" ] && rm -f "$CONF1"
    [ "${IMPL:-}" = "rust2" ] || rmmod umbrawg 2>/dev/null
    return 0
}

[ "$(id -u)" -ne 0 ] && die "root is required (netns, insmod, tcpdump)"
case "$IMPL" in
    rust|rust2|kernel) ;;
    *) die "IMPL must be rust, rust2 or kernel" ;;
esac
[ "$DIR" = "k0" ] || [ "$DIR" = "k1" ] || die "DIR must be k0 or k1"
validate_fec "$KFEC" || die "KFEC must be off, adaptive or K:M"
validate_fec "$RFEC" || die "RFEC must be off, adaptive or K:M"
case "$NETEM_LOSS" in
    ''|*[!0-9.]*) die "NETEM_LOSS must be a percentage number" ;;
esac
[ -x "$UWG" ] || die "uwg binary not found: $UWG"
if [ "$IMPL" = "rust" ] || [ "$IMPL" = "rust2" ]; then
    [ -x "$RUST" ] || die "rust daemon not found: $RUST"
fi
if [ "$IMPL" != "rust2" ]; then
    [ -f "$KO" ] || die "kernel module not found: $KO"
fi
command -v iperf3 >/dev/null 2>&1 || die "iperf3 not found"
command -v python3 >/dev/null 2>&1 || die "python3 not found"

trap cleanup EXIT

mkdir -p "$(dirname "$OUT")" /var/run/umbrawg

remove_namespaces
rm -f /var/run/umbrawg/uwg0.sock /var/run/umbrawg/uwg1.sock
if [ "$IMPL" != "rust2" ]; then
    rmmod umbrawg 2>/dev/null || true
    [ -e /sys/module/umbrawg ] && die "module umbrawg is busy and cannot be unloaded"

    modprobe udp_tunnel 2>/dev/null || true
    modprobe ip6_udp_tunnel 2>/dev/null || true
    insmod "$KO" >"$OUT-insmod.log" 2>&1 || die "insmod failed: $(tail -3 "$OUT-insmod.log" 2>/dev/null)"
fi

ip netns add "$NS0" || die "cannot create netns $NS0"
ip netns add "$NS1" || die "cannot create netns $NS1"
ip link add "$V0" type veth peer name "$V1" || die "cannot create veth pair"
ip link set "$V0" netns "$NS0"
ip link set "$V1" netns "$NS1"
ip -n "$NS0" addr add "$UL0/24" dev "$V0"
ip -n "$NS1" addr add "$UL1/24" dev "$V1"
ip -n "$NS0" link set "$V0" mtu "$UMTU" up
ip -n "$NS1" link set "$V1" mtu "$UMTU" up
ip -n "$NS0" link set lo up
ip -n "$NS1" link set lo up

case "$DIR" in
    k0)
        KNS=$NS0
        ONS=$NS1
        KDEV=$V0
        ODEV=$V1
        KIF=uwg0
        OIF=uwg1
        KIP=$TUN0
        OIP=$TUN1
        KUL=$UL0
        OUL=$UL1
        ;;
    k1)
        KNS=$NS1
        ONS=$NS0
        KDEV=$V1
        ODEV=$V0
        KIF=uwg1
        OIF=uwg0
        KIP=$TUN1
        OIP=$TUN0
        KUL=$UL1
        OUL=$UL0
        ;;
esac

if [ "$IMPL" = "kernel" ]; then
    PEER_FEC=$KFEC
else
    PEER_FEC=$RFEC
fi

if [ "$DIR" = "k0" ]; then
    FEC_SIDE0=$KFEC
    FEC_SIDE1=$PEER_FEC
else
    FEC_SIDE0=$PEER_FEC
    FEC_SIDE1=$KFEC
fi

RUST_ENV_BASE=()
[ -n "$FEC_SHARD" ] && RUST_ENV_BASE+=(UMBRAWG_FEC_SHARD="$FEC_SHARD")
[ -n "$ACK_INTERVAL" ] && RUST_ENV_BASE+=(UMBRAWG_ACK_INTERVAL="$ACK_INTERVAL")
[ -n "$UMBRAWG_THREADS" ] && RUST_ENV_BASE+=(UMBRAWG_THREADS="$UMBRAWG_THREADS")

start_rust_daemon() {
    local ns=$1 ifname=$2 fec=$3 logfile=$4
    ip netns exec "$ns" env UMBRAWG_FEC="$fec" "${RUST_ENV_BASE[@]+"${RUST_ENV_BASE[@]}"}" \
        "$RUST" --foreground "$ifname" >"$logfile" 2>&1 &
    LAST_PID=$!
}

wait_rust_socket() {
    local ifname=$1 logfile=$2
    for _ in $(seq 1 50); do
        [ -S "/var/run/umbrawg/$ifname.sock" ] && return 0
        sleep 0.1
    done
    log "rust daemon did not create $ifname: $(tail -3 "$logfile" 2>/dev/null)"
    return 1
}

if [ "$IMPL" = "rust2" ]; then
    start_rust_daemon "$NS0" uwg0 "$FEC_SIDE0" "$OUT-rust-ns0.log"
    DPID=$LAST_PID
    start_rust_daemon "$NS1" uwg1 "$FEC_SIDE1" "$OUT-rust-ns1.log"
    DPID2=$LAST_PID
    wait_rust_socket uwg0 "$OUT-rust-ns0.log" || die "rust2 daemon (ns0) is not ready"
    wait_rust_socket uwg1 "$OUT-rust-ns1.log" || die "rust2 daemon (ns1) is not ready"
elif [ "$IMPL" = "rust" ]; then
    ip netns exec "$KNS" ip link add "$KIF" type umbrawg || die "cannot create $KIF in $KNS"
    start_rust_daemon "$ONS" "$OIF" "$PEER_FEC" "$OUT-$IMPL.log"
    DPID=$LAST_PID
    wait_rust_socket "$OIF" "$OUT-$IMPL.log" || die "rust daemon did not create $OIF"
else
    ip netns exec "$KNS" ip link add "$KIF" type umbrawg || die "cannot create $KIF in $KNS"
    ip netns exec "$ONS" ip link add "$OIF" type umbrawg || die "cannot create $OIF in $ONS"
fi

ip -n "$NS0" addr add "$TUN0/24" dev uwg0
ip -n "$NS1" addr add "$TUN1/24" dev uwg1
ip -n "$NS0" link set uwg0 mtu "$TUNMTU" up
ip -n "$NS1" link set uwg1 mtu "$TUNMTU" up

K0=$("$UWG" genkey) || die "uwg genkey failed"
K1=$("$UWG" genkey) || die "uwg genkey failed"
P0=$(printf '%s' "$K0" | "$UWG" pubkey) || die "uwg pubkey failed"
P1=$(printf '%s' "$K1" | "$UWG" pubkey) || die "uwg pubkey failed"

CONF0=$(mktemp "${TMPDIR:-/tmp}/wire-ext-conf0.XXXXXX")
CONF1=$(mktemp "${TMPDIR:-/tmp}/wire-ext-conf1.XXXXXX")

write_conf() {
    local file=$1 priv=$2 port=$3 peer=$4 endpoint_ip=$5 endpoint_port=$6 fec=$7
    {
        printf '[Interface]\n'
        printf 'PrivateKey = %s\n' "$priv"
        printf 'ListenPort = %s\n' "$port"
        if [ "$IMPL" != "rust2" ]; then
            printf 'FEC = %s\n' "$fec"
        fi
        printf '\n[Peer]\n'
        printf 'PublicKey = %s\n' "$peer"
        printf 'AllowedIPs = 10.9.0.0/24\n'
        printf 'Endpoint = %s:%s\n' "$endpoint_ip" "$endpoint_port"
        printf 'PersistentKeepalive = 5\n'
    } > "$file"
}

write_conf "$CONF0" "$K0" "$PORT0" "$P1" "$UL1" "$PORT1" "$FEC_SIDE0"
write_conf "$CONF1" "$K1" "$PORT1" "$P0" "$UL0" "$PORT0" "$FEC_SIDE1"

if ! OUT0=$(ip netns exec "$NS0" "$UWG" setconf uwg0 "$CONF0" 2>&1); then
    die "setconf uwg0 failed: $OUT0"
fi
if ! OUT1=$(ip netns exec "$NS1" "$UWG" setconf uwg1 "$CONF1" 2>&1); then
    die "setconf uwg1 failed: $OUT1"
fi

for _ in $(seq 1 40); do
    if ip netns exec "$KNS" ping -c 1 -W 1 "$OIP" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.5
done

apply_netem() {
    local ns=$1 dev=$2
    local args=()
    case "$NETEM_LOSS" in
        ''|0) ;;
        *) args+=(loss "${NETEM_LOSS}%") ;;
    esac
    case "$NETEM_DELAY" in
        ''|0) ;;
        *[!0-9.]*) args+=(delay "$NETEM_DELAY") ;;
        *) args+=(delay "${NETEM_DELAY}ms") ;;
    esac
    case "$NETEM_RATE" in
        ''|0) ;;
        *) args+=(rate "$NETEM_RATE") ;;
    esac
    [ "${#args[@]}" -eq 0 ] && return 0
    ip netns exec "$ns" tc qdisc replace dev "$dev" root netem "${args[@]}"
}

if [ "$READY" = "1" ]; then
    apply_netem "$KNS" "$KDEV" || die "tc netem failed on $KDEV"
    if [ "$NETEM_BOTH" = "1" ]; then
        apply_netem "$ONS" "$ODEV" || die "tc netem failed on $ODEV"
    fi
fi

PLOSS=100
PRTT=-
if [ "$READY" != "1" ]; then
    RESULT=FAIL_LINK
    TCP=FAIL
    UDP=FAIL
    UDP_LOSS=FAIL
    PING_LOSS=FAIL
    FRAG=-
    NPKT=0
else
    if [ "$SKIP_PING" = "1" ]; then
        PING_LOSS=SKIP
    else
        PING_OUT=$(ip netns exec "$KNS" ping -c 10 -i 0.2 -W 1 "$OIP" 2>&1) || true
        PLOSS=$(printf '%s\n' "$PING_OUT" | sed -n 's/.* \([0-9]*\)% packet loss.*/\1/p' | head -1)
        PLOSS=${PLOSS:-100}
        PRTT=$(printf '%s\n' "$PING_OUT" | sed -n 's/.*rtt min\/avg\/max\/mdev = \([^ ]*\).*/\1/p' | head -1)
        PRTT=${PRTT:--}
        PING_LOSS=$PLOSS
    fi

    start_server() {
        local suffix=$1
        SRV_PID=""
        rm -f "$OUT-srv$suffix.pid"
        ip netns exec "$ONS" iperf3 -s -1 -p "$IPERF_PORT" -D \
            --pidfile "$OUT-srv$suffix.pid" --logfile "$OUT-srv$suffix.log" 2>/dev/null || return 1
        sleep 0.3
        SRV_PID=$(cat "$OUT-srv$suffix.pid" 2>/dev/null || true)
        return 0
    }

    stop_server() {
        if [ -n "$SRV_PID" ]; then
            kill "$SRV_PID" 2>/dev/null
            SRV_PID=""
        fi
        ip netns exec "$ONS" pkill -x iperf3 2>/dev/null || true
    }

    CAP_PID=""
    if command -v tcpdump >/dev/null 2>&1; then
        ip netns exec "$ONS" tcpdump -i "$ODEV" -nn -s 128 -c 200000 -w "$OUT.pcap" \
            "udp port $PORT0 or udp port $PORT1" >/dev/null 2>&1 &
        CAP_PID=$!
        sleep 0.2
    fi

    # FEC/underlay policy can lower the interface MTU after setconf, so size
    # the iperf3 blocks from the live MTU instead of the requested TUNMTU.
    DEV_MTU=$(ip netns exec "$KNS" ip -o link show "$KIF" 2>/dev/null |
        sed -n 's/.* mtu \([0-9][0-9]*\).*/\1/p' | head -1)
    [ -n "$DEV_MTU" ] || DEV_MTU=$TUNMTU
    MSS=$((DEV_MTU - 40))
    [ "$MSS" -gt 1420 ] && MSS=1420
    [ "$MSS" -lt 64 ] && MSS=64
    UDPLEN=$((DEV_MTU - 40))
    [ "$UDPLEN" -gt 1340 ] && UDPLEN=1340
    [ "$UDPLEN" -lt 64 ] && UDPLEN=64

    TCP=FAIL
    start_server tcp || true
    TCP_RC=0
    ip netns exec "$KNS" iperf3 -c "$OIP" -p "$IPERF_PORT" -t "$DUR" -P 1 -l "$MSS" -J \
        >"$OUT-tcp.json" 2>"$OUT-tcp.err" || TCP_RC=$?
    stop_server
    if [ "$TCP_RC" -eq 0 ] && [ -s "$OUT-tcp.json" ]; then
        TCP=$(python3 -c 'import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print(round(d["end"]["sum_received"]["bits_per_second"]/1e6,1))
except Exception:
    print("FAIL")' "$OUT-tcp.json")
    fi

    UDP=FAIL
    UDP_LOSS=FAIL
    UDP_RC=0
    sleep 0.3
    start_server udp || true
    ip netns exec "$KNS" iperf3 -c "$OIP" -p "$IPERF_PORT" -t "$DUR" -u -b "$UDP_RATE" -l "$UDPLEN" -J \
        >"$OUT-udp.json" 2>"$OUT-udp.err" || UDP_RC=$?
    stop_server
    if [ "$UDP_RC" -eq 0 ] && [ -s "$OUT-udp.json" ]; then
        UDP_METRICS=$(python3 -c 'import json,sys
try:
    d=json.load(open(sys.argv[1]))
    s=d["end"]["sum"]
    bps=round(s["bits_per_second"]/1e6,1)
    lost=s.get("lost_percent")
    if lost is None:
        packets=s.get("packets",0)
        lost_packets=s.get("lost_packets",0)
        lost=(100.0*lost_packets/packets) if packets else 0.0
    print(f"{bps} {round(float(lost),3)}")
except Exception:
    print("FAIL FAIL")' "$OUT-udp.json")
        UDP=${UDP_METRICS%% *}
        UDP_LOSS=${UDP_METRICS##* }
        [ -z "$UDP" ] && UDP=FAIL
        [ -z "$UDP_LOSS" ] && UDP_LOSS=FAIL
    fi

    if [ -n "$CAP_PID" ]; then
        kill "$CAP_PID" 2>/dev/null
        wait "$CAP_PID" 2>/dev/null
        CAP_PID=""
    fi

    FRAG=-
    NPKT=0
    if [ -s "$OUT.pcap" ]; then
        NPKT=$(tcpdump -nn -r "$OUT.pcap" 2>/dev/null | wc -l)
        NPKT=${NPKT:-0}
        FRAG=$(tcpdump -nn -r "$OUT.pcap" -v 2>/dev/null \
            | grep -cE 'offset [1-9][0-9]*,|flags \[[^]]*\+' || true)
        FRAG=${FRAG:-0}
    fi

    RESULT=OK
    [ "$TCP" = "FAIL" ] && RESULT=FAIL_TCP
    [ "$UDP" = "FAIL" ] && RESULT=FAIL_UDP
fi

log "impl=$IMPL dir=$DIR kernel_fec=$KFEC peer_fec=$PEER_FEC"
log "loss=${NETEM_LOSS}% delay=$NETEM_DELAY rate=${NETEM_RATE:-0} both=$NETEM_BOTH umtu=$UMTU tunmtu=$TUNMTU dur=$DUR"
log "tcp=$TCP Mbit/s udp=$UDP Mbit/s udp_loss=$UDP_LOSS% ping_loss=$PING_LOSS% rtt=$PRTT pkt=$NPKT frag=$FRAG"
log "artifacts=$OUT.*"

printf 'RESULT tag=%s impl=%s dir=%s fec=%s loss=%s tcp_mbit=%s udp_mbit=%s udp_loss=%s ping_loss=%s frag=%s result=%s\n' \
    "$TAG" "$IMPL" "$DIR" "$KFEC" "$NETEM_LOSS" \
    "$TCP" "$UDP" "$UDP_LOSS" "$PING_LOSS" "$FRAG" "$RESULT"

[ "$RESULT" = "OK" ]
