#!/bin/bash
set -u
W=/root/umbrawg
T=$W/bench/.t
UWGBIN=$W/tools/target/release/uwg
mkdir -p $T
cleanup() { for n in lcli lsrv; do ip netns del $n 2>/dev/null; done; }
cleanup
K1=$($UWGBIN genkey); P1=$(echo "$K1" | $UWGBIN pubkey)
K2=$($UWGBIN genkey); P2=$(echo "$K2" | $UWGBIN pubkey)
mkconf() { local priv=$1 listen=$2 pub=$3 ep=$4 out=$5
  { echo "[Interface]"; echo "PrivateKey = $priv"; echo "ListenPort = $listen"; cat $T/obf-lines.txt
    echo; echo "[Peer]"; echo "PublicKey = $pub"; echo "Endpoint = $ep"; echo "AllowedIPs = 10.9.0.0/24"; echo "PersistentKeepalive = 5"; } > "$out"; }
mkconf "$K1" 51820 "$P2" 10.0.0.2:51821 $T/lc.conf
mkconf "$K2" 51821 "$P1" 10.0.0.1:51820 $T/ls.conf
START=$(date +%s.%N)
ip netns add lcli; ip netns add lsrv
ip link add vc type veth peer name vs
ip link set vc netns lcli; ip link set vs netns lsrv
ip -n lcli addr add 10.0.0.1/24 dev vc; ip -n lsrv addr add 10.0.0.2/24 dev vs
for ns in lcli lsrv; do
  ip -n $ns link set lo up; ip -n $ns link set vc up 2>/dev/null; ip -n $ns link set vs up 2>/dev/null
  ip -n $ns link add uwg0 type umbrawg; ip -n $ns link set uwg0 mtu 1420 up
  ip netns exec $ns sysctl -qw net.ipv4.conf.all.rp_filter=0
done
ip -n lcli addr add 10.9.0.1/24 dev uwg0; ip -n lsrv addr add 10.9.0.2/24 dev uwg0
ip netns exec lcli $UWGBIN setconf uwg0 $T/lc.conf
ip netns exec lsrv $UWGBIN setconf uwg0 $T/ls.conf
for pct in 2 10; do
  ip netns exec lcli tc qdisc replace dev vc root netem loss $pct%
  ip netns exec lsrv tc qdisc replace dev vs root netem loss $pct%
  echo "== loss $pct%"
  ip netns exec lcli ping -c 5 -W 2 -i 0.2 10.9.0.2 | tail -2
  ip netns exec lsrv iperf3 -s -1 -D --pidfile /tmp/ls.pid; sleep 0.5
  ip netns exec lcli iperf3 -c 10.9.0.2 -b 100M -t 3 -J > /tmp/lt.json 2>/dev/null
  python3 -c 'import json; s=json.load(open("/tmp/lt.json"))["end"]; print("tcp Mbps=%.1f retr=%s"%(s["sum_received"]["bits_per_second"]/1e6, s["sum_sent"].get("retransmits")))'
  pkill -f "iperf3 -s"; sleep 0.3
  ip netns exec lsrv iperf3 -s -1 -D --pidfile /tmp/ls.pid; sleep 0.5
  ip netns exec lcli iperf3 -c 10.9.0.2 -u -b 100M -t 3 -l 1340 -J > /tmp/lu.json 2>/dev/null
  python3 -c 'import json; s=json.load(open("/tmp/lu.json"))["end"]["sum"]; print("udp Mbps=%.1f lost=%s/%s"%(s["bits_per_second"]/1e6,s["lost_packets"],s["packets"]))'
  pkill -f "iperf3 -s"
  ip netns exec lcli tc qdisc del dev vc root 2>/dev/null
  ip netns exec lsrv tc qdisc del dev vs root 2>/dev/null
done
END=$(date +%s.%N)
python3 -c "print('wall seconds', round($END-$START,1))"
cleanup
echo done
