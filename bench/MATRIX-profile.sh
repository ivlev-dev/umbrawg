#!/bin/bash
# Profile umbrawg: perf record/stat + bpftrace on packet path.
set -u
ROOT=/root/umbrawg
B=$ROOT/bench/matrix
BIN=$ROOT/tools/target/release/uwg
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/bench-lib.sh"
OUT=$B/profile
KO=${KO:-$ROOT/module-baseline/umbrawg.ko}
mkdir -p "$OUT"

cleanup_ns() { for n in mcli mrtr msrv; do ip netns del "$n" 2>/dev/null; done; }
trap 'cleanup_ns; pkill -f "pf-srv.pid"' EXIT

. "$B/keys.env"
P_CLI=$(printf '%s' "$K_CLI" | "$BIN" pubkey)
P_SRV=$(printf '%s' "$K_SRV" | "$BIN" pubkey)

gen_confs() {
  local obf=$1 obf_lines=""
  if [ "$obf" = "1" ]; then
    obf_lines=$(obf_block_from_conf "$ROOT/bench/obf-params.conf" "$BIN" genkey)
  fi
  {
    echo "[Interface]"; echo "PrivateKey = $K_CLI"; echo "ListenPort = 51820"
    [ -n "$obf_lines" ] && printf '%s\n' "$obf_lines"
    echo; echo "[Peer]"; echo "PublicKey = $P_SRV"; echo "Endpoint = 192.168.50.20:51821"
    echo "AllowedIPs = 10.9.0.0/24"; echo "PersistentKeepalive = 5"
  } > "$B/conf-cli"
  {
    echo "[Interface]"; echo "PrivateKey = $K_SRV"; echo "ListenPort = 51821"
    [ -n "$obf_lines" ] && printf '%s\n' "$obf_lines"
    echo; echo "[Peer]"; echo "PublicKey = $P_CLI"; echo "Endpoint = 192.168.50.10:51820"
    echo "AllowedIPs = 10.9.0.0/24"; echo "PersistentKeepalive = 5"
  } > "$B/conf-srv"
}

setup() {
  cleanup_ns
  ip netns add mcli; ip netns add mrtr; ip netns add msrv
  ip link add vc type veth peer name vc2
  ip link add vt type veth peer name vt2
  ip link set vc netns mcli; ip link set vc2 netns mrtr
  ip link set vt netns mrtr; ip link set vt2 netns msrv
  ip -n mcli addr add 10.0.0.1/24 dev vc
  ip -n mrtr addr add 10.0.0.10/24 dev vc2
  ip -n mrtr addr add 192.168.50.10/24 dev vt
  ip -n msrv addr add 192.168.50.20/24 dev vt2
  local ns
  for ns in mcli mrtr msrv; do
    ip -n $ns link set lo up
    ip netns exec $ns sysctl -qw net.ipv4.ip_forward=1
    ip netns exec $ns sysctl -qw net.ipv4.conf.all.rp_filter=0
    ip netns exec $ns sysctl -qw net.ipv4.conf.default.rp_filter=0
  done
  ip -n mcli link set vc up; ip -n mrtr link set vc2 up
  ip -n mrtr link set vt up; ip -n msrv link set vt2 up
  ip -n mcli addr add 10.9.0.1/32 dev lo
  ip -n mcli route add 10.9.0.0/24 via 10.0.0.10
  ip -n mrtr route add 10.9.0.1/32 via 10.0.0.1 dev vc2
}

do_one() {
  local cores=$1 obf=$2 mask cpus pid
  if [ "$cores" = "1" ]; then mask=1; cpus=0; else mask=7; cpus=0-2; fi
  for spec in "mrtr:vt" "mrtr:vc2" "msrv:vt2"; do
    ns=${spec%%:*}; dv=${spec##*:}
    ip netns exec "$ns" sh -c "echo $mask > /sys/class/net/$dv/queues/rx-0/rps_cpus" 2>/dev/null
  done
  gen_confs "$obf"
  for spec in "mrtr:10.9.0.254/24" "msrv:10.9.0.2/24"; do
    ns=${spec%%:*}; ad=${spec##*:}
    ip -n "$ns" link del uwg0 2>/dev/null
    ip -n "$ns" link add uwg0 type umbrawg
    ip -n "$ns" link set uwg0 mtu 1420
    ip -n "$ns" addr add "$ad" dev uwg0
    ip -n "$ns" link set uwg0 up
  done
  ip netns exec mrtr "$BIN" setconf uwg0 "$B/conf-cli"
  ip netns exec msrv "$BIN" setconf uwg0 "$B/conf-srv"
  ip netns exec mcli ping -c 3 -W 2 -I 10.9.0.1 10.9.0.2 >/dev/null 2>&1
  local tag="c${cores}-obf${obf}"
  ip netns exec msrv taskset -c 3 iperf3 -s -1 -p 5290 -D --pidfile /tmp/pf-srv.pid
  sleep 0.5
  ip netns exec mcli taskset -c 3 iperf3 -c 10.9.0.2 -p 5290 -B 10.9.0.1 -t 45 -P "$([ "$cores" = 1 ] && echo 1 || echo 3)" >/dev/null 2>&1 &
  pid=$!
  sleep 3
  perf record -g -C "$cpus" -F 997 -o "$OUT/perf-$tag.data" -- sleep 10 >/dev/null 2>&1
  perf report -i "$OUT/perf-$tag.data" --stdio --no-children -g none --sort symbol 2>/dev/null > "$OUT/perf-$tag.report"
  perf stat -C "$cpus" -e cycles,instructions,branches,branch-misses,cache-misses,cache-references \
    -- sleep 6 > "$OUT/perfstat-$tag.txt" 2>&1
  timeout 12 bpftrace -e 'kprobe:udp_sendmsg { @send[comm, cpu] = count(); }
    kprobe:udp_recvmsg { @recv[comm, cpu] = count(); }
    kprobe:uwg_xmit { @uwg_xmit[cpu] = count(); }
    kprobe:uwg_receive { @uwg_receive[cpu] = count(); }
    interval:s:6 { exit(); }' > "$OUT/bpf-$tag.txt" 2>&1
  wait $pid 2>/dev/null
  pkill -f "pf-srv.pid" 2>/dev/null
}

modprobe amneziawg 2>/dev/null
if [ "$(cat /sys/module/umbrawg/srcversion 2>/dev/null)" != "$(modinfo -F srcversion "$KO")" ]; then
  rmmod umbrawg 2>/dev/null; insmod "$KO"
fi
setup
do_one 1 0
do_one 1 1
do_one 3 0
do_one 3 1
echo profiles-done
