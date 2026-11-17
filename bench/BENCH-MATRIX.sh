#!/bin/bash
# Isolated matrix harness (matrix/ namespace) - does not touch other bench files.
set -u
ROOT=/root/umbrawg
BENCH=$ROOT/bench/matrix
BIN=$ROOT/tools/target/release/uwg
KO=${KO:-$ROOT/module-baseline/umbrawg.ko}
KEYS=$BENCH/keys.env
DUR=${DUR:-3}
CPU_APP=${CPU_APP:-3}
OUT=${OUT:-$BENCH/results.csv}

log() { echo "[matrix] $*" >&2; }

cleanup_ns() { for n in mcli mrtr msrv; do ip netns del "$n" 2>/dev/null; done; }
cleanup_all() { cleanup_ns; pkill -f "mx-srv.pid" 2>/dev/null; }

prepare_keys() {
  if [ -f "$KEYS" ]; then . "$KEYS"; else
    { echo "K_CLI=$($BIN genkey)"; echo "K_SRV=$($BIN genkey)"
      for i in 1 2 3 4; do echo "K_X$i=$($BIN genkey)"; done; } > "$KEYS"
    . "$KEYS"
  fi
  P_CLI=$(printf '%s' "$K_CLI" | "$BIN" pubkey)
  P_SRV=$(printf '%s' "$K_SRV" | "$BIN" pubkey)
  local i k
  for i in 1 2 3 4; do
    eval "k=\$K_X$i"
    eval "P_X$i=\$(printf '%s' \"\$k\" | \"\$BIN\" pubkey)"
  done
}

ensure_module() {
  local want got
  want=$(modinfo -F srcversion "$KO" 2>/dev/null)
  got=$(cat /sys/module/umbrawg/srcversion 2>/dev/null)
  if [ -z "$got" ] || [ "$got" != "$want" ]; then
    rmmod umbrawg 2>/dev/null
    insmod "$KO" || { log "insmod failed"; return 1; }
    got=$(cat /sys/module/umbrawg/srcversion 2>/dev/null)
    [ "$got" = "$want" ] || { log "srcversion mismatch want=$want got=$got"; return 1; }
  fi
  return 0
}

gen_confs() {
  local obf=$1 peers=$2 i pk
  {
    echo "[Interface]"; echo "PrivateKey = $K_CLI"; echo "ListenPort = 51820"
    if [ "$obf" = "1" ]; then
      sed -n '/^\[Interface\]/,/^\[Peer\]/p' "$ROOT/bench/obf-params.conf" \
        | grep -Ev '^(PrivateKey|ListenPort|\[Interface\]|\[Peer\])' | sed '/^[[:space:]]*$/d'
    fi
    echo; echo "[Peer]"; echo "PublicKey = $P_SRV"
    echo "Endpoint = 192.168.50.20:51821"; echo "AllowedIPs = 10.9.0.0/24"
    echo "PersistentKeepalive = 5"
  } > "$BENCH/conf-cli"
  {
    echo "[Interface]"; echo "PrivateKey = $K_SRV"; echo "ListenPort = 51821"
    if [ "$obf" = "1" ]; then
      sed -n '/^\[Interface\]/,/^\[Peer\]/p' "$ROOT/bench/obf-params.conf" \
        | grep -Ev '^(PrivateKey|ListenPort|\[Interface\]|\[Peer\])' | sed '/^[[:space:]]*$/d'
    fi
    echo; echo "[Peer]"; echo "PublicKey = $P_CLI"
    echo "Endpoint = 192.168.50.10:51820"; echo "AllowedIPs = 10.9.0.0/24"
    echo "PersistentKeepalive = 5"
    i=1
    while [ "$i" -lt "$peers" ]; do
      eval "pk=\$P_X$i"
      echo; echo "[Peer]"; echo "PublicKey = $pk"; echo "AllowedIPs = 10.10.$i.0/24"
      i=$((i+1))
    done
  } > "$BENCH/conf-srv"
}

setup_topology() {
  cleanup_ns
  ip netns add mcli; ip netns add mrtr; ip netns add msrv
  ip link add vc type veth peer name vc2
  ip link add vt type veth peer name vt2
  ip link set vc netns mcli
  ip link set vc2 netns mrtr
  ip link set vt netns mrtr
  ip link set vt2 netns msrv
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
  ip -n mcli link set vc up
  ip -n mrtr link set vc2 up
  ip -n mrtr link set vt up
  ip -n msrv link set vt2 up
  ip -n mcli addr add 10.9.0.1/32 dev lo
  ip -n mcli route add 10.9.0.0/24 via 10.0.0.10
  ip -n mrtr route add 10.9.0.1/32 via 10.0.0.1 dev vc2
}

set_rps() {
  local mask=$1 spec ns dev
  for spec in "mrtr:vt" "mrtr:vc2" "msrv:vt2"; do
    ns=${spec%%:*}; dev=${spec##*:}
    ip netns exec "$ns" sh -c "echo $mask > /sys/class/net/$dev/queues/rx-0/rps_cpus" 2>/dev/null
  done
}

setup_cgroup() {
  local cpus=$1 c pid cand
  mkdir -p /sys/fs/cgroup/bench-tunnel 2>/dev/null
  grep -qw cpuset /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || \
    echo +cpuset > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
  echo "$cpus" > /sys/fs/cgroup/bench-tunnel/cpuset.cpus 2>/dev/null
  for c in $(echo "$cpus" | tr ',' ' '); do
    pid=""
    for cand in /proc/[0-9]*; do
      if [ "$(cat "$cand/comm" 2>/dev/null)" = "ksoftirqd/$c" ]; then pid=${cand#/proc/}; break; fi
    done
    [ -n "$pid" ] && echo "$pid" > /sys/fs/cgroup/bench-tunnel/cgroup.procs 2>/dev/null
  done
}

link_dev() {
  local kind=$1 spec ns addr
  for spec in "mrtr:10.9.0.254/24" "msrv:10.9.0.2/24"; do
    ns=${spec%%:*}; addr=${spec##*:}
    ip -n "$ns" link del uwg0 2>/dev/null
    ip -n "$ns" link add uwg0 type "$kind"
    ip -n "$ns" link set uwg0 mtu 1420
    ip -n "$ns" addr add "$addr" dev uwg0
    ip -n "$ns" link set uwg0 up
  done
}

setconf_dev() {
  if [ "$1" = "uwg" ]; then
    ip netns exec mrtr "$BIN" setconf uwg0 "$BENCH/conf-cli" 2>/dev/null || return 1
    ip netns exec msrv "$BIN" setconf uwg0 "$BENCH/conf-srv" 2>/dev/null || return 1
  else
    ip netns exec mrtr awg setconf uwg0 "$BENCH/conf-cli" 2>/dev/null || return 1
    ip netns exec msrv awg setconf uwg0 "$BENCH/conf-srv" 2>/dev/null || return 1
  fi
}

wait_link() {
  local i
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    ip netns exec mcli ping -c 1 -W 1 -I 10.9.0.1 10.9.0.2 >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  return 1
}

set_loss() {
  ip netns exec mrtr tc qdisc del dev vt root 2>/dev/null
  [ "$1" != "0" ] && ip netns exec mrtr tc qdisc add dev vt root netem loss "$1%"
  return 0
}

foreign_load() { pgrep -f 'traffic\.py|sniff\.py|uwgbench|bench/lib\.sh' >/dev/null 2>&1 && echo 1 || echo 0; }

ensure_cpus() {
  local c st fixed=0
  for c in 0 1 2 3 4 5; do
    st=$(cat /sys/devices/system/cpu/cpu$c/online 2>/dev/null || echo 1)
    if [ "$st" = "0" ]; then
      echo 1 > /sys/devices/system/cpu/cpu$c/online 2>/dev/null && fixed=1
    fi
  done
  if [ $fixed -eq 1 ]; then sleep 0.5; fi
  echo $fixed
}

wait_quiet() {
  local i q
  for i in 1 2 3 4 5 6 7 8; do
    q=$(foreign_load)
    [ "$q" = "0" ] && return 0
    sleep 1
  done
  return 0
}

run_one() {
  local module=$1 cores=$2 proto=$3 rate=$4 loss=$5 obf=$6 peers=$7
  local kind setter flows mask cpus per_flow args rc contended cpufix
  wait_quiet
  contended=$(foreign_load)
  cpufix=$(ensure_cpus)
  [ "$cpufix" = "1" ] && contended=1
  case $module in
    umbrawg) kind=umbrawg; setter=uwg;;
    amneziawg) kind=amneziawg; setter=awg;;
  esac
  if [ "$cores" = "1" ]; then flows=1; mask=1; cpus=0; else flows=3; mask=7; cpus=0-2; fi
  set_rps "$mask"; setup_cgroup "$cpus"
  gen_confs "$obf" "$peers"
  link_dev "$kind"
  if ! setconf_dev "$setter"; then
    echo "$module,$cores,$flows,$proto,$rate,$loss,$obf,$peers,FAIL_SETCONF,0,0,0,0,$contended" >> "$OUT"
    log "SETCONF FAIL $module c=$cores $proto ${rate}M loss=$loss obf=$obf p=$peers"; return
  fi
  set_loss "$loss"
  if ! wait_link; then
    echo "$module,$cores,$flows,$proto,$rate,$loss,$obf,$peers,FAIL_LINK,0,0,0,0,$contended" >> "$OUT"
    log "LINK FAIL $module c=$cores $proto ${rate}M loss=$loss obf=$obf p=$peers"; set_loss 0; return
  fi
  per_flow=$(awk -v r="$rate" -v f="$flows" 'BEGIN{printf "%.4f", r/f}')
  args="-c 10.9.0.2 -p 5290 -B 10.9.0.1 -t $DUR -P $flows -J --connect-timeout 8000"
  if [ "$proto" = "udp" ]; then
    if [ "$rate" = "0" ]; then args="$args -u -b 0 -l 1340"; else args="$args -u -b ${per_flow}M -l 1340"; fi
  else
    if [ "$rate" != "0" ]; then args="$args -b ${per_flow}M"; fi
    args="$args -M 1380"
  fi
  ip netns exec msrv taskset -c "$CPU_APP" iperf3 -s -1 -p 5290 -D --pidfile /tmp/mx-srv.pid 2>/dev/null
  local w
  for w in 1 2 3 4 5 6 7 8; do
    ip netns exec msrv ss -ltn 2>/dev/null | grep -q ':5290 ' && break
    sleep 0.2
  done
  sleep 0.15
  ip netns exec mcli timeout 25 taskset -c "$CPU_APP" iperf3 $args > /tmp/mx-out.json 2>/tmp/mx-err.txt
  rc=$?
  if [ $rc -ne 0 ]; then
    sleep 0.5
    ip netns exec msrv taskset -c "$CPU_APP" iperf3 -s -1 -p 5290 -D --pidfile /tmp/mx-srv2.pid 2>/dev/null
    for w in 1 2 3 4 5 6 7 8; do
      ip netns exec msrv ss -ltn 2>/dev/null | grep -q ':5290 ' && break
      sleep 0.2
    done
    sleep 0.15
    ip netns exec mcli timeout 25 taskset -c "$CPU_APP" iperf3 $args > /tmp/mx-out.json 2>/tmp/mx-err.txt
    rc=$?
  fi
  pkill -f "mx-srv" 2>/dev/null
  if [ $rc -ne 0 ]; then
    echo "$module,$cores,$flows,$proto,$rate,$loss,$obf,$peers,FAIL_IPERF_$rc,0,0,0,0,$contended" >> "$OUT"
    log "IPERF FAIL($rc) $module c=$cores $proto ${rate}M loss=$loss obf=$obf p=$peers $(tail -1 /tmp/mx-err.txt)"
    set_loss 0; return
  fi
  python3 - "$module" "$cores" "$flows" "$proto" "$rate" "$loss" "$obf" "$peers" "$contended" >> "$OUT" <<'PY'
import json, sys
m, cores, flows, proto, rate, loss, obf, peers, contended = sys.argv[1:10]
d = json.load(open('/tmp/mx-out.json'))
e = d['end']
if proto == 'udp':
    s = e['sum']; rx = s['bits_per_second']/1e6
    lost = s.get('lost_packets', 0); tot = s.get('packets', 0); retr = 0
    lpct = 100.0*lost/tot if tot else 0.0
else:
    s = e['sum_received']; rx = s['bits_per_second']/1e6
    retr = e['sum_sent'].get('retransmits', 0); lost = 0; lpct = 0.0
rtt = e.get('sum', {}).get('mean_rtt', 0) or 0
print(f"{m},{cores},{flows},{proto},{rate},{loss},{obf},{peers},{rx:.1f},{retr},{lost},{lpct:.2f},{rtt:.1f},{contended}")
PY
  log "$module c=$cores $proto ${rate}M loss=$loss obf=$obf p=$peers -> $(tail -1 "$OUT")"
  set_loss 0
}

stage_smoke() {
  run_one umbrawg 1 tcp 100 0 1 1
  run_one umbrawg 1 udp 100 0 1 1
  run_one amneziawg 1 tcp 100 0 1 1
  run_one amneziawg 1 udp 100 0 1 1
  run_one umbrawg 3 tcp 100 0 0 4
  run_one umbrawg 3 tcp 100 2 0 4
}

stage1() {
  local m c p r o
  for m in umbrawg amneziawg; do for c in 1 3; do for p in tcp udp; do for r in 1 100 500; do
    for o in 0 1; do run_one "$m" "$c" "$p" "$r" 0 "$o" 1; done
    for o in 0 1; do run_one "$m" "$c" "$p" "$r" 0 "$o" 4; done
  done; done; done; done
}

stage2() {
  local m p l o
  for m in umbrawg amneziawg; do for p in tcp udp; do for l in 2 5 10; do for o in 0 1; do
    run_one "$m" 1 "$p" 100 "$l" "$o" 1
  done; done; done; done
}

stage3() {
  local m c p
  for m in umbrawg amneziawg; do for c in 1 3; do for p in tcp udp; do
    run_one "$m" "$c" "$p" 100 0 1 5
    run_one "$m" "$c" "$p" 500 0 1 5
  done; done; done
}

stage4() {
  local m c p o
  for m in umbrawg amneziawg; do for c in 1 3; do for p in tcp udp; do for o in 0 1; do
    run_one "$m" "$c" "$p" 10 0 "$o" 1
  done; done; done; done
}

stage5() {
  local m c p o
  for m in umbrawg amneziawg; do for c in 1 3; do for p in tcp udp; do for o in 0 1; do
    run_one "$m" "$c" "$p" 0 0 "$o" 1
  done; done; done; done
}

main() {
  local stage=${1:-smoke}
  mkdir -p "$BENCH"
  prepare_keys
  modprobe amneziawg 2>/dev/null
  ensure_module || exit 1
  [ -s "$OUT" ] || echo "module,cores,flows,proto,target_mbps,loss_pct,obf,peers,received_mbps,retransmits,lost_packets,lost_pct,rtt_us,contended" > "$OUT"
  setup_topology
  trap 'cleanup_all' EXIT
  case $stage in
    smoke) stage_smoke;;
    stage1) stage1;;
    stage2) stage2;;
    stage3) stage3;;
    stage4) stage4;;
    stage5) stage5;;
    *) log "unknown stage"; exit 1;;
  esac
  log "stage $stage done"
}

main "$@"
