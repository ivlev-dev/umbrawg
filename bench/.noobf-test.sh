#!/bin/bash
set -u
W=/root/umbrawg
T=/root/umbrawg/bench/.t
mkdir -p $T
UWGBIN=$W/tools/target/release/uwg

cleanup() { ip netns del bcli 2>/dev/null; ip netns del bsrv 2>/dev/null; }
cleanup

K1=$($UWGBIN genkey); P1=$(echo "$K1" | $UWGBIN pubkey)
K2=$($UWGBIN genkey); P2=$(echo "$K2" | $UWGBIN pubkey)

write_conf() {
  local priv=$1 listen=$2 pub=$3 ep=$4 out=$5
  printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = 10.9.0.0/24\nPersistentKeepalive = 5\n' \
    "$priv" "$listen" "$pub" "$ep" > "$out"
}
write_conf "$K1" 51820 "$P2" 10.0.0.2:51821 "$T/cli-noobf.conf"
write_conf "$K2" 51821 "$P1" 10.0.0.1:51820 "$T/srv-noobf.conf"
cat "$T/cli-noobf.conf"

ip netns add bcli; ip netns add bsrv
ip link add veth-cli type veth peer name veth-srv
ip link set veth-cli netns bcli; ip link set veth-srv netns bsrv
ip -n bcli addr add 10.0.0.1/24 dev veth-cli
ip -n bsrv addr add 10.0.0.2/24 dev veth-srv
for ns in bcli bsrv; do
  ip -n $ns link set lo up
  ip -n $ns link set veth-cli up 2>/dev/null
  ip -n $ns link set veth-srv up 2>/dev/null
  ip -n $ns link add uwg0 type umbrawg
  ip -n $ns link set uwg0 mtu 1420 up
done
ip -n bcli addr add 10.9.0.1/24 dev uwg0
ip -n bsrv addr add 10.9.0.2/24 dev uwg0
ip netns exec bcli $UWGBIN setconf uwg0 "$T/cli-noobf.conf" && echo setconf-cli-ok
ip netns exec bsrv $UWGBIN setconf uwg0 "$T/srv-noobf.conf" && echo setconf-srv-ok
ip netns exec bcli ping -c 3 -W 2 -s 1392 -M do 10.9.0.2 | tail -2
echo "-- tcp"
ip netns exec bsrv iperf3 -s -1 -D --pidfile /tmp/ipn.pid; sleep 0.6
ip netns exec bcli iperf3 -c 10.9.0.2 -t 3 -J | python3 -c 'import json,sys; s=json.load(sys.stdin)["end"]; print("tcp Mbps=%.1f"%((s["sum_received"]["bits_per_second"])/1e6))'
echo "-- udp 100M"
ip netns exec bsrv iperf3 -s -1 -D --pidfile /tmp/ipu.pid; sleep 0.6
ip netns exec bcli iperf3 -c 10.9.0.2 -u -b 100M -t 3 -l 1340 -J | python3 -c 'import json,sys; s=json.load(sys.stdin)["end"]["sum"]; print("udp Mbps=%.1f lost=%s/%s"%(s["bits_per_second"]/1e6,s["lost_packets"],s["packets"]))'
pkill -f "iperf3 -s"
cleanup
echo done
