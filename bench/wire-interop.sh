#!/bin/bash
set -uo pipefail

KO=${KO:-/root/umbrawg/module-master/src/umbrawg.ko}
IMPL=${IMPL:-rust}
OBF=${OBF:-0}
DIR=${DIR:-k0}
TAG=${TAG:-run}
DUR=${DUR:-2}
UMTU=${UMTU:-9000}
TUNMTU=${TUNMTU:-1420}
UWG=/root/umbrawg/tools/target/release/uwg
RUST=/root/umbrawg/rust/target/release/umbrawg
GO=/opt/baseline/amneziawg-go
NS0=wkg0
NS1=wkg1
V0=wkgv0
V1=wkgv1
PORT0=53920
PORT1=53921
OUT=/tmp/interop-$TAG
OBFCONF=/root/umbrawg/bench/obf-compat.conf
CAP_PID=""
SRV_PID=""
DPID0=""
DPID1=""

log() { echo "[$TAG] $*"; }

cleanup() {
    set +e
    [ -n "$CAP_PID" ] && kill "$CAP_PID" 2>/dev/null
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    for p in $DPID0 $DPID1; do kill "$p" 2>/dev/null; done
    pkill -f "umbrawg --foreground uwg[01]" 2>/dev/null
    pkill -f "amneziawg-go.*uwg[01]" 2>/dev/null
    sleep 0.2
    ip netns del "$NS0" 2>/dev/null
    ip netns del "$NS1" 2>/dev/null
    rm -f /var/run/umbrawg/uwg0.sock /var/run/umbrawg/uwg1.sock
    rm -f /var/run/amneziawg/uwg0.sock /var/run/amneziawg/uwg1.sock
    rmmod umbrawg 2>/dev/null
    rmmod amneziawg 2>/dev/null
}
trap cleanup EXIT

snmp_frag() {
    local ns=$1
    ip netns exec "$ns" awk '/^Ip:/{if(h){print $(i["FragOKs"]), $(i["FragFails"]), $(i["FragCreates"]), $(i["ReasmReqds"]), $(i["ReasmOKs"]), $(i["ReasmFails"]); exit} for(n=2;n<=NF;n++) i[$n]=n; h=1}' /proc/net/snmp
}

cleanup
mkdir -p /var/run/umbrawg /var/run/amneziawg

modprobe udp_tunnel 2>/dev/null
modprobe ip6_udp_tunnel 2>/dev/null
insmod "$KO" || { log INSGOM_FAILED; exit 1; }
ip netns add "$NS0" || exit 1
ip netns add "$NS1" || exit 1
ip link add "$V0" type veth peer name "$V1" || exit 1
ip link set "$V0" netns "$NS0"
ip link set "$V1" netns "$NS1"
ip -n "$NS0" addr add 192.168.77.1/24 dev "$V0"
ip -n "$NS1" addr add 192.168.77.2/24 dev "$V1"
ip -n "$NS0" link set "$V0" mtu "$UMTU" up
ip -n "$NS1" link set "$V1" mtu "$UMTU" up
ip -n "$NS0" link set lo up
ip -n "$NS1" link set lo up

KNS=$NS0; UNS=$NS1; KIF=uwg0; UIF=uwg1; KIP=10.9.0.1; UIP=10.9.0.2
if [ "$DIR" = "k1" ]; then
    KNS=$NS1; UNS=$NS0; KIF=uwg1; UIF=uwg0; KIP=10.9.0.2; UIP=10.9.0.1
fi
KIP_TARGET=$UIP
REVF=""
[ "${REV:-0}" = "1" ] && REVF="-R"
ip netns exec "$KNS" ip link add "$KIF" type umbrawg || exit 1

case "$IMPL" in
    rust)
        UMBRAWG_THREADS=2 ip netns exec "$UNS" "$RUST" --foreground "$UIF" >"$OUT-$IMPL.log" 2>&1 &
        DPID1=$!
        for _ in $(seq 1 50); do [ -S "/var/run/umbrawg/$UIF.sock" ] && break; sleep 0.1; done
        ;;
    go)
        GOMAXPROCS=2 ip netns exec "$UNS" "$GO" -f "$UIF" >"$OUT-$IMPL.log" 2>&1 &
        DPID1=$!
        for _ in $(seq 1 50); do [ -S "/var/run/amneziawg/$UIF.sock" ] && break; sleep 0.1; done
        ;;
    kernel)
        ip netns exec "$UNS" ip link add "$UIF" type umbrawg || exit 1
        ;;
    amneziawg)
        modprobe amneziawg || exit 1
        ip netns exec "$UNS" ip link add "$UIF" type amneziawg || exit 1
        ;;
esac

ip -n "$NS0" addr add 10.9.0.1/24 dev uwg0
ip -n "$NS1" addr add 10.9.0.2/24 dev uwg1
ip -n "$NS0" link set uwg0 mtu "$TUNMTU" up
ip -n "$NS1" link set uwg1 mtu "$TUNMTU" up

K0=$("$UWG" genkey); K1=$("$UWG" genkey)
P0=$(printf '%s' "$K0" | "$UWG" pubkey); P1=$(printf '%s' "$K1" | "$UWG" pubkey)
OBFBLOCK=""
[ "$OBF" = "1" ] && OBFBLOCK=$(cat "$OBFCONF")

CONF0=$(mktemp); CONF1=$(mktemp)
printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n%s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.9.0.0/24\nEndpoint = 192.168.77.2:%s\nPersistentKeepalive = 5\n' "$K0" "$PORT0" "$OBFBLOCK" "$P1" "$PORT1" > "$CONF0"
printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n%s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.9.0.0/24\nEndpoint = 192.168.77.1:%s\nPersistentKeepalive = 5\n' "$K1" "$PORT1" "$OBFBLOCK" "$P0" "$PORT0" > "$CONF1"

setconf() {
    local ns=$1 if=$2 conf=$3
    case "$IMPL" in
        go|amneziawg)
            if ip netns exec "$ns" awg setconf "$if" "$conf" 2>&1; then :; else ip netns exec "$ns" "$UWG" setconf "$if" "$conf" 2>&1; fi ;;
        *) ip netns exec "$ns" "$UWG" setconf "$if" "$conf" 2>&1 ;;
    esac
}
RC0=$(setconf "$NS0" uwg0 "$CONF0"); R0=$?
RC1=$(setconf "$NS1" uwg1 "$CONF1"); R1=$?
if [ $R0 -ne 0 ] || [ $R1 -ne 0 ]; then
    log "SETCONF_FAILED rc0=$R0($RC0) rc1=$R1($RC1)"
    exit 1
fi

snmp_before0=$(snmp_frag "$NS0"); snmp_before1=$(snmp_frag "$NS1")

wait_ready=0
for _ in $(seq 1 40); do
    if ip netns exec "$KNS" ping -c 1 -W 1 "$KIP_TARGET" >/dev/null 2>&1; then wait_ready=$((_*0)); break; fi
    sleep 0.5
done
HSWAIT=${HSWAIT:-$wait_ready}
PING=$(ip netns exec "$KNS" ping -c 10 -i 0.2 -W 1 "$KIP_TARGET" 2>&1)
PLOSS=$(printf '%s' "$PING" | sed -n 's/.* \([0-9]*\)% packet loss.*/\1/p'); PLOSS=${PLOSS:-100}
PRTT=$(printf '%s' "$PING" | sed -n 's/.*rtt min\/avg\/max\/mdev = \([^ ]*\).*/\1/p'); PRRTT=${PRTT:--}

srv_ns=$NS1; cli_ns=$NS0
if [ "$DIR" = "k1" ]; then srv_ns=$NS1; cli_ns=$NS0; fi
ip netns exec "$srv_ns" iperf3 -s -1 -D --pidfile "$OUT-srv.pid" --logfile "$OUT-srv.log" 2>/dev/null
SRV_PID=$(cat "$OUT-srv.pid" 2>/dev/null)
sleep 0.5

cap_ns=$UNS; cap_if=$V1
[ "$UNS" = "$NS0" ] && cap_if=$V0
ip netns exec "$cap_ns" tcpdump -i "$cap_if" -nn -s 128 -c 20000 -w "$OUT.pcap" '(udp port '$PORT0' or udp port '$PORT1')' >/dev/null 2>&1 &
CAP_PID=$!
sleep 0.3
if [ "${RX_GRO_OFF:-0}" = "1" ]; then ip netns exec "$UNS" ethtool -K "$cap_if" gro off >/dev/null 2>&1; fi
if [ "${TX_UDPSEG_OFF:-0}" = "1" ]; then ip netns exec "$KNS" ethtool -K "$( [ "$KNS" = "$NS0" ] && echo "$V0" || echo "$V1" )" tx-udp-segmentation off >/dev/null 2>&1; fi

TCP=$(ip netns exec "$cli_ns" iperf3 -c 10.9.0.2 -t "$DUR" -P 1 -l 1420 $REVF -J 2>"$OUT-tcp.err" | python3 -c 'import sys,json
try:
 d=json.load(sys.stdin); print(round(d["end"]["sum_received"]["bits_per_second"]/1e6,1))
except Exception: print("FAIL")' )
sleep 0.5
kill "$CAP_PID" 2>/dev/null; wait "$CAP_PID" 2>/dev/null; CAP_PID=""

ip netns exec "$srv_ns" iperf3 -s -1 -D --pidfile "$OUT-srv2.pid" --logfile "$OUT-srv2.log" 2>/dev/null
sleep 0.5
UDP=$(ip netns exec "$cli_ns" iperf3 -c 10.9.0.2 -t "$DUR" -u -b 400M -l 1340 $REVF -J 2>"$OUT-udp.err" | python3 -c 'import sys,json
try:
 d=json.load(sys.stdin); s=d["end"]["sum"]; print(str(round(s["bits_per_second"]/1e6,1))+"/"+str(round(s.get("lost_percent",-1),1)))
except Exception: print("FAIL")' )

snmp_after0=$(snmp_frag "$NS0"); snmp_after1=$(snmp_frag "$NS1")

SIZES="none"
if [ -s "$OUT.pcap" ]; then
    SIZES=$(tcpdump -nn -r "$OUT.pcap" -q 2>/dev/null | sed -n 's/.*UDP, length \([0-9]*\).*/\1/p' | sort -n | uniq -c | sort -rn | head -6 | awk '{printf "%sx%s ", $1, $2}')
    FRAGS=$(tcpdump -nn -r "$OUT.pcap" -v 2>/dev/null | grep -cE 'offset [1-9][0-9]*,|flags \[[^]]*\+')
    NPKT=$(tcpdump -nn -r "$OUT.pcap" 2>/dev/null | wc -l)
else
    FRAGS=-; NPKT=0
fi

H0=""; H1=""
case "$IMPL" in
    go|amneziawg) H0=$(ip netns exec "$NS1" awg show uwg1 2>/dev/null | grep -c "latest handshake" || true) ;;
    *) H0=$(ip netns exec "$NS1" "$UWG" show uwg1 2>/dev/null | grep -c "latest handshake" || true) ;;
esac

log "impl=$IMPL obf=$OBF dir=$DIR ko=$(basename $(dirname $(dirname $KO))) hs_wait=$HSWAIT ping_loss=$PLOSS% rtt=$PRRTT tcp=$TCP Mbit/s udp=$UDP Mbit/s pkt=$NPKT frag=$FRAGS sizes=[$SIZES] snmp0={$snmp_before0 -> $snmp_after0} snmp1={$snmp_before1 -> $snmp_after1} peer_hs=$H0"
log "pcaps=$OUT.pcap logs=$OUT-$IMPL.log"
if [ "$PLOSS" != "0" ]; then
    tail -4 "$OUT-$IMPL.log" 2>/dev/null | sed 's/^/  log: /'
fi
