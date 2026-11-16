#!/bin/bash
set -euo pipefail

RUSTDIR=${RUSTDIR:-/root/umbrawg/rust}
MODDIR=${MODDIR:-/root/umbrawg/module/src}
UWG=${UWG:-/root/umbrawg/tools/target/release/uwg}
DAEMON=${DAEMON:-$RUSTDIR/target/release/umbrawg}
GO_BASELINE=${GO_BASELINE:-/opt/baseline/amneziawg-go}
OBF=${OBF:-/root/umbrawg/bench/obf-params.conf}
RESULT=${RESULT:-/root/umbrawg/bench/results.csv}

NS0=bn0
NS1=bn1
IF0=uwgb0
IF1=uwgb1
V0=bveth0
V1=bveth1
PORT0=51820
PORT1=51821
IPERF_CPU=${IPERF_CPU:-3}
TUNNEL_CPUS_1=${TUNNEL_CPUS_1:-0}
TUNNEL_CPUS_3=${TUNNEL_CPUS_3:-0-2}
DURATION=${DURATION:-3}
PEERS_LIST=${PEERS_LIST:-"1 4"}
CONNS_LIST=${CONNS_LIST:-"1 100"}
LOSS_LIST=${LOSS_LIST:-"0"}
OBF_LIST=${OBF_LIST:-"0 1"}
IMPL_LIST=${IMPL_LIST:-"kernel-umbrawg kernel-amneziawg rust go"}
MODE_LIST=${MODE_LIST:-"1c 3c"}
PROTO_LIST=${PROTO_LIST:-"tcp udp"}
SMOKE=${SMOKE:-0}

if [ "$SMOKE" = "1" ]; then
    IMPL_LIST="kernel-umbrawg rust"
    MODE_LIST="1c"
    PROTO_LIST="tcp"
    CONNS_LIST="1"
    LOSS_LIST="0"
    OBF_LIST="1"
    PEERS_LIST="1"
fi

cleanup() {
    set +e
    pkill -f "umbrawg --foreground $IF0" 2>/dev/null
    pkill -f "umbrawg --foreground $IF1" 2>/dev/null
    pkill -f "amneziawg-go $IF0" 2>/dev/null
    pkill -f "amneziawg-go $IF1" 2>/dev/null
    ip netns del "$NS0" 2>/dev/null
    ip netns del "$NS1" 2>/dev/null
    rm -f "/var/run/umbrawg/$IF0.sock" "/var/run/umbrawg/$IF1.sock"
    rm -f "/var/run/amneziawg/$IF0.sock" "/var/run/amneziawg/$IF1.sock"
    rmmod umbrawg 2>/dev/null
    rmmod amneziawg 2>/dev/null
    echo all > /sys/devices/virtual/workqueue/cpumask 2>/dev/null
}
trap cleanup EXIT

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
    ip link add "$V0" type veth peer name "$V1"
    ip link set "$V0" netns "$NS0"
    ip link set "$V1" netns "$NS1"
    ip -n "$NS0" addr add 192.168.77.1/24 dev "$V0"
    ip -n "$NS1" addr add 192.168.77.2/24 dev "$V1"
    ip -n "$NS0" link set "$V0" up
    ip -n "$NS1" link set "$V1" up
    ip -n "$NS0" link set lo up
    ip -n "$NS1" link set lo up
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
    local k0 k1 p0 p1 obfblock extra0 extra1 i
    k0=$("$UWG" genkey)
    k1=$("$UWG" genkey)
    p0=$(printf '%s' "$k0" | "$UWG" pubkey)
    p1=$(printf '%s' "$k1" | "$UWG" pubkey)
    obfblock=""
    if [ "$obf" = "1" ]; then
        obfblock=$(grep -vE '^(PrivateKey|ListenPort|PublicKey|AllowedIPs|\[Peer\]|\[Interface\])' "$OBF" || true)
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
    printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n%s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.9.0.0/24\nEndpoint = 192.168.77.2:%s\nPersistentKeepalive = 5\n%s\n' \
        "$k0" "$PORT0" "$obfblock" "$p1" "$PORT1" "$extra0" > "$out0"
    printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n%s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.9.0.0/24\nEndpoint = 192.168.77.1:%s\nPersistentKeepalive = 5\n%s\n' \
        "$k1" "$PORT1" "$obfblock" "$p0" "$PORT0" "$extra1" > "$out1"
}

bring_up_addrs() {
    ip -n "$NS0" addr add 10.9.0.1/24 dev "$IF0"
    ip -n "$NS1" addr add 10.9.0.2/24 dev "$IF1"
    ip -n "$NS0" link set "$IF0" mtu 1420 up
    ip -n "$NS1" link set "$IF1" mtu 1420 up
}

start_impl() {
    local impl=$1
    local mode=$2
    local threads=1
    local cpus
    if [ "$mode" = "3c" ]; then
        cpus=$TUNNEL_CPUS_3
        threads=3
    else
        cpus=$TUNNEL_CPUS_1
    fi
    case "$impl" in
        kernel-umbrawg)
            modprobe udp_tunnel; modprobe ip6_udp_tunnel
            insmod "$MODDIR/umbrawg.ko"
            ip netns exec "$NS0" ip link add "$IF0" type umbrawg
            ip netns exec "$NS1" ip link add "$IF1" type umbrawg
            ;;
        kernel-amneziawg)
            modprobe udp_tunnel; modprobe ip6_udp_tunnel
            modprobe amneziawg
            ip netns exec "$NS0" ip link add "$IF0" type amneziawg
            ip netns exec "$NS1" ip link add "$IF1" type amneziawg
            ;;
        rust)
            UMBRAWG_THREADS=$threads ip netns exec "$NS0" taskset -c "$cpus" "$DAEMON" --foreground "$IF0" >/tmp/bench-$IF0.log 2>&1 &
            UMBRAWG_THREADS=$threads ip netns exec "$NS1" taskset -c "$cpus" "$DAEMON" --foreground "$IF1" >/tmp/bench-$IF1.log 2>&1 &
            for _ in $(seq 1 50); do
                [ -S "/var/run/umbrawg/$IF0.sock" ] && [ -S "/var/run/umbrawg/$IF1.sock" ] && break
                sleep 0.1
            done
            ;;
        go)
            GOMAXPROCS=$threads ip netns exec "$NS0" taskset -c "$cpus" "$GO_BASELINE" "$IF0" >/tmp/bench-$IF0.log 2>&1 &
            GOMAXPROCS=$threads ip netns exec "$NS1" taskset -c "$cpus" "$GO_BASELINE" "$IF1" >/tmp/bench-$IF1.log 2>&1 &
            for _ in $(seq 1 50); do
                [ -S "/var/run/amneziawg/$IF0.sock" ] && [ -S "/var/run/amneziawg/$IF1.sock" ] && break
                sleep 0.1
            done
            ;;
    esac
}

apply_config() {
    local impl=$1
    local conf0=$2
    local conf1=$3
    case "$impl" in
        kernel-amneziawg|go)
            awg_ns "$NS0" setconf "$IF0" "$conf0"
            awg_ns "$NS1" setconf "$IF1" "$conf1"
            ;;
        *)
            uwg_ns "$NS0" setconf "$IF0" "$conf0"
            uwg_ns "$NS1" setconf "$IF1" "$conf1"
            ;;
    esac
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

run_iperf() {
    local proto=$1
    local conns=$2
    if [ "$proto" = "tcp" ]; then
        ip netns exec "$NS1" taskset -c "$IPERF_CPU" iperf3 -s -1 -D --logfile /tmp/bench-srv.log
        sleep 0.3
        ip netns exec "$NS0" taskset -c "$IPERF_CPU" iperf3 -c 10.9.0.2 -t "$DURATION" -P "$conns" -l 1420 -J > /tmp/bench-client.json
        python3 -c 'import json;d=json.load(open("/tmp/bench-client.json"));print(round(d["end"]["sum_received"]["bits_per_second"]/1e6,1), d["end"]["sum_sent"].get("retransmits",0))'
    else
        ip netns exec "$NS1" taskset -c "$IPERF_CPU" iperf3 -s -1 -D --logfile /tmp/bench-srv.log
        sleep 0.3
        ip netns exec "$NS0" taskset -c "$IPERF_CPU" iperf3 -c 10.9.0.2 -t "$DURATION" -P "$conns" -u -b 1000M -l 1340 -J > /tmp/bench-client.json
        python3 -c 'import json;d=json.load(open("/tmp/bench-client.json"));s=d["end"]["sum"];print(round(s["bits_per_second"]/1e6,1), round(s.get("lost_percent",0),3))'
    fi
}

: > "$RESULT"
echo "impl,mode,proto,conns,loss,obf,peers,mbit,extra" >> "$RESULT"

mkdir -p /var/run/umbrawg

for impl in $IMPL_LIST; do
    for mode in $MODE_LIST; do
        if [ "$mode" = "1c" ]; then
            cpus=$TUNNEL_CPUS_1
        else
            cpus=$TUNNEL_CPUS_3
        fi
        if [ "$impl" = "kernel-umbrawg" ] || [ "$impl" = "kernel-amneziawg" ]; then
            echo "$cpus" > /sys/devices/virtual/workqueue/cpumask 2>/dev/null || true
        fi
        for obf in $OBF_LIST; do
            for peers in $PEERS_LIST; do
                cleanup
                sleep 0.3
                setup_topology
                start_impl "$impl" "$mode"
                bring_up_addrs
                conf0=$(mktemp)
                conf1=$(mktemp)
                make_configs "$obf" "$peers" "$conf0" "$conf1"
                apply_config "$impl" "$conf0" "$conf1"
                if ! wait_tunnel; then
                    echo "TUNNEL_FAILED impl=$impl mode=$mode obf=$obf peers=$peers" >&2
                    tail -5 "/tmp/bench-$IF1.log" 2>/dev/null || true
                    continue
                fi
                for loss in $LOSS_LIST; do
                    set_loss "$loss"
                    for proto in $PROTO_LIST; do
                        for conns in $CONNS_LIST; do
                            out=$(run_iperf "$proto" "$conns")
                            mbit=$(echo "$out" | awk '{print $1}')
                            extra=$(echo "$out" | awk '{print $2}')
                            echo "$impl,$mode,$proto,$conns,$loss,$obf,$peers,$mbit,$extra" >> "$RESULT"
                            echo "$impl $mode $proto c=$conns loss=$loss obf=$obf peers=$peers -> $mbit Mbit/s ($extra)"
                        done
                    done
                done
                rm -f "$conf0" "$conf1"
            done
        done
    done
done

echo "RESULTS=$RESULT"
