#!/bin/bash
set -uo pipefail
export LC_ALL=C

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/bench-lib.sh"

KO=${KO:-/root/umbrawg/module-master/src/umbrawg.ko}
UWG=${UWG:-/root/umbrawg/tools/target/release/uwg}
OBF_FILE=${OBF_FILE:-/root/umbrawg/bench/obf-params.conf}
OBF=${OBF:-0}
DURATION=${DURATION:-30}
PERF_SECS=${PERF_SECS:-10}
PERF_FREQ=${PERF_FREQ:-999}
STAT_SECS=${STAT_SECS:-5}
RPS_MASK=${RPS_MASK:-off}
BACKLOG=${BACKLOG:-1000}
GRO_BATCH=${GRO_BATCH:-8}
OUT=${OUT:-/root/umbrawg/bench/tmp/p0-obf$OBF}
CALLGRAPH=${CALLGRAPH:-bpf}

NS0=bn0; NS1=bn1; IF0=uwgb0; IF1=uwgb1; V0=bveth0; V1=bveth1
PORT0=51820; PORT1=51821
IPERF_CPU=${IPERF_CPU:-3}
TUNNEL_CPUS=${TUNNEL_CPUS:-0-2}

WQ=/sys/devices/virtual/workqueue/cpumask
OLD_WQ=$(cat "$WQ" 2>/dev/null || echo 3f)
OLD_BACKLOG=$(cat /proc/sys/net/core/netdev_max_backlog)
OLD_GRO=$(cat /proc/sys/net/core/gro_normal_batch)
OLD_RPS_FLOW=$(cat /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || echo 0)

cleanup() {
    set +e
    [ -n "${CLI:-}" ] && kill "$CLI" 2>/dev/null
    [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null
    [ -n "${PERFPID:-}" ] && kill "$PERFPID" 2>/dev/null
    ip netns del "$NS0" 2>/dev/null
    ip netns del "$NS1" 2>/dev/null
    rmmod umbrawg 2>/dev/null
    echo "$OLD_WQ" > "$WQ" 2>/dev/null
    echo "$OLD_BACKLOG" > /proc/sys/net/core/netdev_max_backlog 2>/dev/null
    echo "$OLD_GRO" > /proc/sys/net/core/gro_normal_batch 2>/dev/null
    echo "$OLD_RPS_FLOW" > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null
}
trap cleanup EXIT

mkdir -p "$OUT"
echo "== setup obf=$OBF rps=$RPS_MASK backlog=$BACKLOG gro=$GRO_BATCH cg=$CALLGRAPH"
modprobe udp_tunnel || exit 1
modprobe ip6_udp_tunnel || exit 1
rmmod umbrawg 2>/dev/null
insmod "$KO" || exit 1
# build cpumask from list like 0-2
mask=0
for part in $(echo "$TUNNEL_CPUS" | tr ',' ' '); do
    if [[ $part == *-* ]]; then
        a=${part%-*}; b=${part#*-}
        for ((i=a;i<=b;i++)); do mask=$((mask | (1<<i))); done
    else
        mask=$((mask | (1<<part)))
    fi
done
printf '%x\n' "$mask" > "$WQ"
echo "$BACKLOG" > /proc/sys/net/core/netdev_max_backlog
echo "$GRO_BATCH" > /proc/sys/net/core/gro_normal_batch

ip netns add "$NS0" || exit 1
ip netns add "$NS1" || exit 1
ip link add "$V0" type veth peer name "$V1" numtxqueues 6 numrxqueues 6 || exit 1
ip link set "$V0" netns "$NS0"
ip link set "$V1" netns "$NS1"
ip -n "$NS0" link set "$V0" mtu 9000
ip -n "$NS1" link set "$V1" mtu 9000
ip -n "$NS0" addr add 192.168.77.1/24 dev "$V0"
ip -n "$NS1" addr add 192.168.77.2/24 dev "$V1"
ip -n "$NS0" link set "$V0" up
ip -n "$NS1" link set "$V1" up
ip -n "$NS0" link set lo up
ip -n "$NS1" link set lo up
ip netns exec "$NS0" ethtool -L "$V0" rx 6 tx 6 >/dev/null 2>&1 || true
ip netns exec "$NS1" ethtool -L "$V1" rx 6 tx 6 >/dev/null 2>&1 || true

ip netns exec "$NS0" ip link add "$IF0" type umbrawg || exit 1
ip netns exec "$NS1" ip link add "$IF1" type umbrawg || exit 1
ip -n "$NS0" addr add 10.9.0.1/24 dev "$IF0"
ip -n "$NS1" addr add 10.9.0.2/24 dev "$IF1"
ip -n "$NS0" link set "$IF0" mtu 1420 up
ip -n "$NS1" link set "$IF1" mtu 1420 up

K0=$("$UWG" genkey); P0=$(printf %s "$K0" | "$UWG" pubkey)
K1=$("$UWG" genkey); P1=$(printf %s "$K1" | "$UWG" pubkey)
obfblock=""
if [ "$OBF" = "1" ]; then
    obfblock=$(obf_block_from_conf "$OBF_FILE" "$UWG" genkey)
fi
printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n%s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.9.0.0/24\nEndpoint = 192.168.77.2:%s\nPersistentKeepalive = 5\n' \
    "$K0" "$PORT0" "$obfblock" "$P1" "$PORT1" > /tmp/p0-0.conf
printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n%s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.9.0.0/24\nEndpoint = 192.168.77.1:%s\nPersistentKeepalive = 5\n' \
    "$K1" "$PORT1" "$obfblock" "$P0" "$PORT0" > /tmp/p0-1.conf
ip netns exec "$NS0" "$UWG" setconf "$IF0" /tmp/p0-0.conf || exit 1
ip netns exec "$NS1" "$UWG" setconf "$IF1" /tmp/p0-1.conf || exit 1
ok=0
for _ in $(seq 1 60); do
    if ip netns exec "$NS0" ping -c1 -W1 10.9.0.2 >/dev/null 2>&1; then ok=1; break; fi
    sleep 0.3
done
[ "$ok" = 1 ] || { echo "TUNNEL_FAILED"; exit 1; }

if [ "$RPS_MASK" != "off" ]; then
    for ns in "$NS0" "$NS1"; do
        ip netns exec "$ns" sh -c "for q in /sys/class/net/$IF0/queues/rx-*; do echo $RPS_MASK > \$q/rps_cpus; done"
        ip netns exec "$ns" sh -c "for q in /sys/class/net/$IF1/queues/rx-*; do echo $RPS_MASK > \$q/rps_cpus; done"
    done
    echo "rps set: ns0=$(ip netns exec "$NS0" sh -c "cat /sys/class/net/$IF0/queues/rx-0/rps_cpus" 2>/dev/null) ns1=$(ip netns exec "$NS1" sh -c "cat /sys/class/net/$IF1/queues/rx-0/rps_cpus" 2>/dev/null)"
fi

snap_softnet() { cp /proc/net/softnet_stat "$1"; }
snap_softnet "$OUT/softnet.before"
ip -n "$NS0" -s link show "$IF0" > "$OUT/link0.before" 2>&1
ip -n "$NS1" -s link show "$IF1" > "$OUT/link1.before" 2>&1
ip -n "$NS1" -s link show "$V1" > "$OUT/veth1.before" 2>&1
nstat -az > "$OUT/nstat.before" 2>/dev/null || true
ip netns exec "$NS0" nstat -az > "$OUT/nstat0.before" 2>/dev/null || true
ip netns exec "$NS1" nstat -az > "$OUT/nstat1.before" 2>/dev/null || true
ip netns exec "$NS1" tc -s qdisc show dev "$V1" > "$OUT/qdisc1.before" 2>&1 || true

ip netns exec "$NS1" taskset -c "$IPERF_CPU" iperf3 -s -1 -D --pidfile /tmp/p0-srv.pid --logfile /tmp/p0-srv.log >/dev/null 2>&1
SRV=$(cat /tmp/p0-srv.pid)
sleep 0.5
ip netns exec "$NS0" taskset -c "$IPERF_CPU" iperf3 -c 10.9.0.2 -P 10 -t "$DURATION" -l 1420 -J > "$OUT/iperf.json" 2>"$OUT/iperf.err" &
CLI=$!
sleep 2
ps -eLo pid,tid,psr,pcpu,comm --sort=-pcpu > "$OUT/threads.txt" 2>&1 || true
ip netns exec "$NS1" ss -tin > "$OUT/ss1.txt" 2>&1 || true

if [ "$PERF_SECS" != "0" ]; then
    if [ "$CALLGRAPH" = "bpf" ]; then
        CG=(--call-graph bpf)
    elif [ "$CALLGRAPH" = "dwarf" ]; then
        CG=(--call-graph dwarf)
    elif [ "$CALLGRAPH" = "fp" ]; then
        CG=(--call-graph fp)
    else
        CG=()
    fi
    perf record -a "${CG[@]}" -F "$PERF_FREQ" -o "$OUT/perf.data" -- sleep "$PERF_SECS" > "$OUT/perf-record.log" 2>&1
    echo "perf record rc=$? size=$(stat -c %s "$OUT/perf.data" 2>/dev/null)"
fi

if [ "$STAT_SECS" != "0" ]; then
    perf stat -a -e irq_vectors:reschedule_entry -e irq_vectors:call_function_entry \
        -e irq_vectors:call_function_single_entry -e sched:sched_switch \
        -- sleep "$STAT_SECS" > "$OUT/perf-stat.txt" 2>&1 || true
fi

wait "$CLI" 2>/dev/null
snap_softnet "$OUT/softnet.after"
ip -n "$NS0" -s link show "$IF0" > "$OUT/link0.after" 2>&1
ip -n "$NS1" -s link show "$IF1" > "$OUT/link1.after" 2>&1
ip -n "$NS1" -s link show "$V1" > "$OUT/veth1.after" 2>&1
nstat -az > "$OUT/nstat.after" 2>/dev/null || true
ip netns exec "$NS0" nstat -az > "$OUT/nstat0.after" 2>/dev/null || true
ip netns exec "$NS1" nstat -az > "$OUT/nstat1.after" 2>/dev/null || true
ip netns exec "$NS1" tc -s qdisc show dev "$V1" > "$OUT/qdisc1.after" 2>&1 || true
python3 - "$OUT" <<'PY'
import sys,os
out=sys.argv[1]
def parse_nstat(p):
    d={}
    for ln in open(p):
        f=ln.split()
        if len(f)>=2 and f[0].isdigit(): d[f[1]]=int(f[0])
    return d
try:
    a=parse_nstat(out+"/nstat.before"); b=parse_nstat(out+"/nstat.after")
    keys=["TcpRetransSegs","TcpOutSegs","TcpInSegs","TcpExtTCPLostRetransmit","TcpExtTCPTimeouts","TcpExtTCPOFOQueue","TcpExtTCPBacklogDrop","TcpExtListenDrops","IpInReceives","IpInDelivers","UdpInDatagrams","UdpInErrors","IpExtInOctets","IpExtOutOctets"]
    print("NSTAT_DELTA " + " ".join("%s=%d"%(k,b.get(k,0)-a.get(k,0)) for k in keys if k in b))
except Exception as e:
    print("NSTAT_FAIL",e)
PY
python3 - "$OUT/iperf.json" <<'PY'
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    e=d["end"]
    print("IPERF_MBIT=%.1f retrans=%s" % (e["sum_received"]["bits_per_second"]/1e6, e["sum_sent"].get("retransmits")))
except Exception as ex:
    print("IPERF_PARSE_FAIL", ex)
PY
kill "$SRV" 2>/dev/null
echo "== done $OUT"
