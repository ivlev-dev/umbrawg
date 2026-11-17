#!/bin/bash
set -u
W=/root/umbrawg
T=/root/umbrawg/bench/.t
mkdir -p $T
UWGBIN=$W/tools/target/release/uwg
CONF=$W/bench/obf-params.conf

cleanup() {
  ip netns del bcli 2>/dev/null
  ip netns del bsrv 2>/dev/null
}
cleanup

gen_conf() {
  local name=$1 priv=$2 listen=$3 pub=$4 endpoint=$5 out=$6
  {
    echo "[Interface]"
    echo "PrivateKey = $priv"
    echo "ListenPort = $listen"
    sed -n '/^\[Interface\]/,/^\[Peer\]/p' "$CONF" \
      | grep -Ev '^(PrivateKey|ListenPort|\[Interface\]|\[Peer\])' \
      | sed '/^[[:space:]]*$/d'
    echo
    echo "[Peer]"
    echo "PublicKey = $pub"
    echo "Endpoint = $endpoint"
    echo "AllowedIPs = 10.9.0.0/24"
    echo "PersistentKeepalive = 5"
  } > "$out"
}

K1=$($UWGBIN genkey); P1=$(echo "$K1" | $UWGBIN pubkey)
K2=$($UWGBIN genkey); P2=$(echo "$K2" | $UWGBIN pubkey)
gen_conf cli "$K1" 51820 "$P2" 10.0.0.2:51821 "$T/cli.conf"
gen_conf srv "$K2" 51821 "$P1" 10.0.0.1:51820 "$T/srv.conf"
echo "== generated cli.conf:"; sed -n 1,8p "$T/cli.conf"
echo "== obf lines count:"; grep -cE '^(H[1-4]|S[1-4]|Jc|Jmin|Jmax|I[1-5]|HeaderProtectionKey|ContentPaddingAddition|RekeyAfterTime|RekeyTimeout|RejectAfterTime|KeepaliveTimeout|MaxHandshakeAttempts|RandomTrailers|DisableCookies)' "$T/cli.conf"

setup() {
  local kind=$1
  cleanup
  ip netns add bcli
  ip netns add bsrv
  ip link add veth-cli type veth peer name veth-srv
  ip link set veth-cli netns bcli
  ip link set veth-srv netns bsrv
  ip -n bcli addr add 10.0.0.1/24 dev veth-cli
  ip -n bsrv addr add 10.0.0.2/24 dev veth-srv
  for ns in bcli bsrv; do
    ip -n $ns link set lo up
    ip -n $ns link set veth-cli up 2>/dev/null
    ip -n $ns link set veth-srv up 2>/dev/null
    ip -n $ns link set mtu 1500 dev veth-cli 2>/dev/null
    ip -n $ns link set mtu 1500 dev veth-srv 2>/dev/null
    ip netns exec $ns sysctl -qw net.ipv4.conf.all.rp_filter=0
    ip -n $ns link add uwg0 type $kind
    ip -n $ns link set uwg0 mtu 1420
  done
  ip -n bcli addr add 10.9.0.1/24 dev uwg0
  ip -n bsrv addr add 10.9.0.2/24 dev uwg0
  ip -n bcli link set uwg0 up
  ip -n bsrv link set uwg0 up
}

run_kind() {
  local kind=$1 setter=$2
  echo "===== kind=$kind setter=$setter"
  setup "$kind"
  ip netns exec bcli $setter setconf uwg0 "$T/cli.conf" 2>&1 | head -5
  ip netns exec bsrv $setter setconf uwg0 "$T/srv.conf" 2>&1 | head -5
  ip netns exec bcli $setter show uwg0 2>&1 | head -25
  echo "-- ping"
  ip netns exec bcli ping -c 3 -W 2 -s 1392 -M do 10.9.0.2 2>&1 | tail -3
  echo "-- iperf3 tcp 3s"
  ip netns exec bsrv iperf3 -s -1 -D --pidfile /tmp/iperf_$kind.pid 2>&1 | head -2
  sleep 0.6
  ip netns exec bcli iperf3 -c 10.9.0.2 -t 3 -J 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); s=d["end"]; print("tcp Mbps=%.1f retrans=%s"%(s["sum_received"]["bits_per_second"]/1e6, s.get("sum_sent",{}).get("retransmits")))' 2>&1
  echo "-- iperf3 udp 100M 3s"
  ip netns exec bsrv iperf3 -s -1 -D --pidfile /tmp/iperf_udp_$kind.pid 2>&1 | head -2
  sleep 0.6
  ip netns exec bcli iperf3 -c 10.9.0.2 -u -b 100M -t 3 -l 1340 -J 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); s=d["end"]["sum"]; print("udp Mbps=%.1f lost=%s/%s"%(s["bits_per_second"]/1e6, s["lost_packets"], s["packets"]))' 2>&1
  pkill -f "iperf3 -s" 2>/dev/null
  ip netns del bcli; ip netns del bsrv
}

run_kind umbrawg "$UWGBIN"
run_kind amneziawg awg
cleanup
echo done
