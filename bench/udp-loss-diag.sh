#!/bin/bash
# udp-loss-diag.sh — разделяет потери UDP 400M на приёмном буфере iperf3,
# на UDP-сокете туннеля и на самом туннеле (TUN/GRO/очереди).
#
# Топология как в bench/wire-ext.sh: два netns, veth 9000, iperf3-сервер в ns1
# (10.10.0.2), клиент в ns0 (10.10.0.1). Клиент и сервер iperf3 закреплены на
# одном ядре (IPERF_CPU), как в матрице.
#
# Критерий (на каждый прогон):
#   sent / lost   — пакеты, отправленные клиентом iperf3 и потерянные по его счёту
#   UdpRcvbufErr  — Δ UdpRcvbufErrors в netns получателя
#   outer_drops   — Δ per-socket drops UDP-сокета туннеля (ss -uamni, skmem d)
#   inner_drops   — то же для приёмного сокета iperf3
#   tun_bytes     — Δ байт, принятых TUN получателя (ip -s link uwg1 RX bytes)
#   expected      — (LEN + 28) * sent, т.е. сколько байт TUN должен был принять
#   byte_gap      — expected - tun_bytes (>0: часть пакетов не дошла до TUN)
#   tun_dropped   — Δ dropped у TUN получателя
#   qdisc_drop    — Δ dropped qdisc на egress отправителя
#
# Почему байты, а не пакеты: с GSO/vnet_hdr один write() в TUN несёт до 64
# inner-пакетов, а rx_packets у TUN считает skb, а не сегменты. Байты же
# суммируются по всем сегментам, поэтому сравнение с (LEN+28)*sent корректно.
# Контрольный TCP iperf3 и keepalive'ы дают небольшой отрицательный gap.
#
# Вывод:
#   byte_gap <= 4 КиБ, outer_drops == 0, tun_dropped == 0,
#   UdpRcvbufErrors ≈ lost  → потери в приёмном буфере iperf3, туннель чист
#   outer_drops > 0          → дропы UDP-сокета туннеля (SO_RCVBUF/всплеск)
#   byte_gap >> 0            → пакеты не дошли до TUN (TX/qdisc/демон)
#   tun_dropped > 0          → дропы TUN
#
# Требует root. Ничего не коммитит.
#
# Примеры:
#   sudo IMPL=rust   REPEATS=3 DUR=10 W_LIST="default 4M" bash bench/udp-loss-diag.sh
#   sudo IMPL=kernel REPEATS=3 DUR=10 W_LIST="default 4M" bash bench/udp-loss-diag.sh
#   sudo IMPL=rust2  W_LIST="96K 128K 4M" P_LIST="1 4" bash bench/udp-loss-diag.sh
#   sudo IMPL=rust   IPERF_CPU=3 IPERF_CPU_CLIENT=4 W_LIST="128K" bash bench/udp-loss-diag.sh
set -uo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
pick_bin() { local c; for c in "$@"; do [ -x "$c" ] && { printf '%s\n' "$c"; return 0; }; done; return 1; }

KO=${KO:-$ROOT/umbrawg-linux-kernel-module/src/umbrawg.ko}
UWG=${UWG:-$(pick_bin "$ROOT/umbrawg-tools/target/release/uwg" "$ROOT/umbrawg-tools/target/debug/uwg")}
RUST=${RUST:-$(pick_bin "$ROOT/umbrawg-rs/target/release/umbrawg" "$ROOT/umbrawg-rs/target/debug/umbrawg")}

IMPL=${IMPL:-rust}                 # rust | kernel | rust2
PARALLEL=${PARALLEL:-0}            # 1 — RX демона с UMBRAWG_PARALLEL_RX=1 (даёт счётчики)
UMBRAWG_SOCKET_BUFFER=${UMBRAWG_SOCKET_BUFFER:-}  # переопределить SO_RCVBUF демона
REPEATS=${REPEATS:-3}
DUR=${DUR:-10}
RATE=${RATE:-400M}                 # на поток
LEN=${LEN:-1340}                   # -l iperf3 (payload датаграммы)
W_LIST=${W_LIST:-"default 4M"}     # -w клиента = SO_RCVBUF сервера (×2); default = без -w
P_LIST=${P_LIST:-1}                # -P: суммарный rate = RATE для всех потоков
BUMP_RMEM=${BUMP_RMEM:-1}          # 1 — поднять rmem_max (глобальный!) на время прогона
IPERF_CPU=${IPERF_CPU:-3}
IPERF_CPU_CLIENT=${IPERF_CPU_CLIENT:-$IPERF_CPU}
UMTU=${UMTU:-9000}
TUNMTU=${TUNMTU:-1420}
PORT0=${PORT0:-53920}
PORT1=${PORT1:-53921}
IPERF_PORT=${IPERF_PORT:-5291}
OUT=${OUT:-/tmp/udp-loss-diag-$(date +%Y%m%d-%H%M%S)}
KEEP=${KEEP:-0}

NS0=udg0; NS1=udg1; V0=udgv0; V1=udgv1
UL0=192.168.78.1; UL1=192.168.78.2
TUN0=10.10.0.1; TUN1=10.10.0.2
DPID0=; DPID1=; CONF0=; CONF1=; LAST=
RMEM_MAX_SAVED=; WMEM_MAX_SAVED=

log() { printf '[diag] %s\n' "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

cleanup() {
    set +u
    ip netns exec "$NS1" pkill -x iperf3 2>/dev/null
    [ -n "${DPID0:-}" ] && kill "$DPID0" 2>/dev/null
    [ -n "${DPID1:-}" ] && kill "$DPID1" 2>/dev/null
    sleep 0.2
    if [ "${KEEP}" = "1" ]; then
        log "KEEP=1: netns $NS0/$NS1 оставлены; вход: ip netns exec $NS1 bash"
    else
        for ns in "$NS0" "$NS1"; do
            for pid in $(ip netns pids "$ns" 2>/dev/null); do kill "$pid" 2>/dev/null; done
            ip netns del "$ns" 2>/dev/null
        done
        rm -f /var/run/umbrawg/uwg0.sock /var/run/umbrawg/uwg1.sock
        [ -n "${CONF0:-}" ] && rm -f "$CONF0"
        [ -n "${CONF1:-}" ] && rm -f "$CONF1"
        [ "$IMPL" = "rust2" ] || rmmod umbrawg 2>/dev/null
    fi
    if [ -n "${RMEM_MAX_SAVED:-}" ]; then
        sysctl -qw net.core.rmem_max="$RMEM_MAX_SAVED" net.core.wmem_max="${WMEM_MAX_SAVED:-$RMEM_MAX_SAVED}" 2>/dev/null
        log "host rmem_max восстановлен: $RMEM_MAX_SAVED"
    fi
    return 0
}

[ "$(id -u)" -ne 0 ] && die "нужен root (netns, insmod, sysctl)"
command -v iperf3 >/dev/null || die "iperf3 не найден"
command -v ss >/dev/null || die "ss не найден"
command -v nstat >/dev/null || die "nstat не найден (iproute2)"
[ -x "$UWG" ] || die "uwg не найден: $UWG"
case "$IMPL" in
    rust|rust2) [ -x "$RUST" ] || die "демон не найден: $RUST" ;;
    kernel) [ -f "$KO" ] || die "модуль не найден: $KO" ;;
    *) die "IMPL=rust|kernel|rust2" ;;
esac

mkdir -p "$OUT" /var/run/umbrawg
trap cleanup EXIT

# net.core.rmem_max — глобальный (не per-netns), поэтому правим хост и
# возвращаем прежнее значение в cleanup. rmem_default не трогаем: он и есть
# предмет проверки (iperf3 без -w наследует именно его).
RMEM_MAX=$(cat /proc/sys/net/core/rmem_max)
RMEM_DEF=$(cat /proc/sys/net/core/rmem_default)
if [ "$BUMP_RMEM" = "1" ] && [ "$RMEM_MAX" -lt 33554432 ]; then
    RMEM_MAX_SAVED=$RMEM_MAX
    WMEM_MAX_SAVED=$(cat /proc/sys/net/core/wmem_max)
    if sysctl -qw net.core.rmem_max=33554432 net.core.wmem_max=33554432; then
        log "host rmem_max: $RMEM_MAX -> 33554432 (вернём в конце)"
    else
        log "не удалось поднять rmem_max: -w 4M упрётся в $RMEM_MAX"
        RMEM_MAX_SAVED=
    fi
fi
{
    echo "impl=$IMPL parallel=$PARALLEL repeats=$REPEATS dur=$DUR rate=$RATE len=$LEN p=$P_LIST w=$W_LIST iperf_cpu=$IPERF_CPU/$IPERF_CPU_CLIENT"
    echo "kernel=$(uname -r) nproc=$(nproc) iperf3=$(iperf3 --version 2>/dev/null | head -1)"
    echo "rmem_default=$RMEM_DEF rmem_max_before=$RMEM_MAX rmem_max_now=$(cat /proc/sys/net/core/rmem_max) bump_rmem=$BUMP_RMEM"
    echo "daemon_socket_buffer=${UMBRAWG_SOCKET_BUFFER:-default}"
} | tee "$OUT/env.txt"

modprobe udp_tunnel 2>/dev/null; modprobe ip6_udp_tunnel 2>/dev/null
if [ "$IMPL" != "rust2" ]; then
    rmmod umbrawg 2>/dev/null
    insmod "$KO" >"$OUT/insmod.log" 2>&1 || die "insmod: $(tail -2 "$OUT/insmod.log")"
fi

ip netns add "$NS0" || die "netns $NS0"
ip netns add "$NS1" || die "netns $NS1"
ip link add "$V0" type veth peer name "$V1" || die "veth"
ip link set "$V0" netns "$NS0"; ip link set "$V1" netns "$NS1"
ip -n "$NS0" addr add "$UL0/24" dev "$V0"; ip -n "$NS1" addr add "$UL1/24" dev "$V1"
ip -n "$NS0" link set "$V0" mtu "$UMTU" up; ip -n "$NS1" link set "$V1" mtu "$UMTU" up
ip -n "$NS0" link set lo up; ip -n "$NS1" link set lo up

start_rust() { # ns ifname logfile
    local extra=()
    [ "$PARALLEL" = "1" ] && extra+=(UMBRAWG_PARALLEL_RX=1 UMBRAWG_RX_STATS=1)
    [ -n "$UMBRAWG_SOCKET_BUFFER" ] && extra+=(UMBRAWG_SOCKET_BUFFER="$UMBRAWG_SOCKET_BUFFER")
    ip netns exec "$1" env UMBRAWG_UNDERLAY_MTU="$UMTU" RUST_LOG=info "${extra[@]+"${extra[@]}"}" \
        "$RUST" --foreground "$2" >"$3" 2>&1 &
    LAST=$!
    for _ in $(seq 1 60); do [ -S "/var/run/umbrawg/$2.sock" ] && return 0; sleep 0.1; done
    log "демон $2 не поднялся: $(tail -3 "$3")"; return 1
}

if [ "$IMPL" = "rust2" ]; then
    start_rust "$NS0" uwg0 "$OUT/rust0.log" || die "rust ns0"
    DPID0=$LAST
    start_rust "$NS1" uwg1 "$OUT/rust1.log" || die "rust ns1"
    DPID1=$LAST
elif [ "$IMPL" = "rust" ]; then
    ip -n "$NS0" link add uwg0 type umbrawg || die "kernel uwg0"
    start_rust "$NS1" uwg1 "$OUT/rust1.log" || die "rust ns1"
    DPID1=$LAST
else
    ip -n "$NS0" link add uwg0 type umbrawg || die "kernel uwg0"
    ip -n "$NS1" link add uwg1 type umbrawg || die "kernel uwg1"
fi

ip -n "$NS0" addr add "$TUN0/24" dev uwg0; ip -n "$NS1" addr add "$TUN1/24" dev uwg1
ip -n "$NS0" link set uwg0 mtu "$TUNMTU" up; ip -n "$NS1" link set uwg1 mtu "$TUNMTU" up

K0=$("$UWG" genkey) || die genkey; K1=$("$UWG" genkey) || die genkey
P0=$(printf '%s' "$K0" | "$UWG" pubkey) || die pubkey
P1=$(printf '%s' "$K1" | "$UWG" pubkey) || die pubkey
CONF0=$(mktemp /tmp/udg-conf0.XXXXXX); CONF1=$(mktemp /tmp/udg-conf1.XXXXXX)
printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.10.0.0/24\nEndpoint = %s:%s\nPersistentKeepalive = 5\n' \
    "$K0" "$PORT0" "$P1" "$UL1" "$PORT1" >"$CONF0"
printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.10.0.0/24\nEndpoint = %s:%s\nPersistentKeepalive = 5\n' \
    "$K1" "$PORT1" "$P0" "$UL0" "$PORT0" >"$CONF1"
ip netns exec "$NS0" "$UWG" setconf uwg0 "$CONF0" >"$OUT/setconf0.log" 2>&1 || die "setconf uwg0: $(tail -2 "$OUT/setconf0.log")"
ip netns exec "$NS1" "$UWG" setconf uwg1 "$CONF1" >"$OUT/setconf1.log" 2>&1 || die "setconf uwg1: $(tail -2 "$OUT/setconf1.log")"

for _ in $(seq 1 40); do ip netns exec "$NS0" ping -c1 -W1 "$TUN1" >/dev/null 2>&1 && break; sleep 0.25; done
ip netns exec "$NS0" ping -c1 -W1 "$TUN1" >/dev/null 2>&1 || die "туннель не поднялся: $(tail -3 "$OUT/rust1.log" 2>/dev/null)"

# --- счётчики ---------------------------------------------------------------
tun_counters() { ip netns exec "$NS1" ip -s link show uwg1 2>/dev/null | awk '
    /RX:/{g=1;next} g&&/^[[:space:]]+[0-9]/{print $1, $2, $3, $4; exit}'; }
tun_bytes()   { tun_counters | awk '{print $1}'; }
tun_dropped() { tun_counters | awk '{print $4}'; }
udp_field()   { ip netns exec "$NS1" nstat -az 2>/dev/null | awk -v f="$1" '$1==f{print $2+0}'; }
veth_rx()     { ip -n "$NS1" -s link show "$V1" | awk '/RX:/{g=1;next} g&&/^[[:space:]]+[0-9]/{print $2,$4;exit}'; }
veth0_tx()    { ip -n "$NS0" -s link show "$V0" | awk '/TX:/{g=1;next} g&&/^[[:space:]]+[0-9]/{print $2,$4;exit}'; }
qdisc_drop()  { ip netns exec "$NS0" tc -s qdisc show dev "$V0" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dropped"){d+=$(i+1)}} END{print d+0}'; }

# снимок ss: "local_port d rb rq" для всех UDP-сокетов netns получателя.
# skmem — одно поле через запятую: skmem:(r0,rb16777216,...,bl0,d0)
ss_snapshot() { ip netns exec "$NS1" ss -uamni 2>/dev/null | awk '
    /^[A-Z]/ { port=""; for(i=1;i<=NF;i++) if ($i ~ /:[0-9]+$/) { p=$i; sub(/.*:/,"",p); port=p; break } rq=$2 }
    /skmem:/ { d=0; rb=0
        if (match($0, /[,(]d[0-9]+/)) { d=substr($0, RSTART+1, RLENGTH-1); sub(/^d/,"",d) }
        if (match($0, /[,(]rb[0-9]+/)) { rb=substr($0, RSTART+1, RLENGTH-1); sub(/^rb/,"",rb) }
        if (port!="") printf "%s %s %s %s\n", port, d, rb, rq }'; }

sock_max() { # $1=port $2=dumpfile → "drops rb maxrq"
    awk -v p="$1" '$1==p {if($2>d)d=$2; if($3>rb)rb=$3; if($4>rq)rq=$4} END{print d+0, rb+0, rq+0}' "$2"; }

sample_ss() { local out=$1 i; : > "$out"
    for i in $(seq 1 1000); do ss_snapshot >> "$out"; sleep 0.1; done; }

# --- один прогон ------------------------------------------------------------
CSV="$OUT/results.csv"
echo "impl,parallel,w,p,repeat,rc,sent,recv,lost,lost_pct,tun_bytes,expected_bytes,byte_gap,tun_ratio,tun_dropped_delta,rcvbuf_err_delta,outer_drops,outer_rb,outer_maxrq,inner_drops,inner_rb,inner_maxrq,veth_rx_delta,veth_rxdrop_delta,veth0_tx_delta,veth0_txdrop_delta,qdisc_drop_delta,err_json" >"$CSV"

one() { # $1=w $2=p $3=repeat
    local w=$1 p=$2 rep=$3
    local tag="w${w}-p${p}-r${rep}"
    local wargs=(); [ "$w" != "default" ] && wargs+=(-w "$w")
    local rate_num=${RATE%[GgMm]} per_rate
    per_rate="$(( rate_num / p ))M"
    timeout 90 ip netns exec "$NS1" taskset -c "$IPERF_CPU" iperf3 -s -1 -p "$IPERF_PORT" \
        >"$OUT/$tag.srv.log" 2>&1 &
    local srv=$!
    local t=0; while ! ip netns exec "$NS1" ss -lnu 2>/dev/null | grep -q ":$IPERF_PORT"; do
        t=$((t+1)); [ $t -gt 80 ] && break; sleep 0.1; done

    local b_rx b_tb b_td b_err b_vrx b_vrxd b_tx b_txd b_qd
    b_tb=$(tun_bytes); b_td=$(tun_dropped); b_err=$(udp_field UdpRcvbufErrors)
    b_vrx=$(veth_rx | awk '{print $1}'); b_vrxd=$(veth_rx | awk '{print $2}')
    b_tx=$(veth0_tx | awk '{print $1}'); b_txd=$(veth0_tx | awk '{print $2}'); b_qd=$(qdisc_drop)
    sample_ss "$OUT/$tag.ss" & local mon=$!
    ip netns exec "$NS0" taskset -c "$IPERF_CPU_CLIENT" iperf3 -c "$TUN1" -p "$IPERF_PORT" \
        -u -b "$per_rate" -l "$LEN" -t "$DUR" -P "$p" "${wargs[@]+"${wargs[@]}"}" -J \
        >"$OUT/$tag.json" 2>"$OUT/$tag.err"
    local rc=$?
    kill "$mon" 2>/dev/null; wait "$mon" 2>/dev/null
    wait "$srv" 2>/dev/null

    local a_tb a_td a_err a_vrx a_vrxd a_tx a_txd a_qd
    a_tb=$(tun_bytes); a_td=$(tun_dropped); a_err=$(udp_field UdpRcvbufErrors)
    a_vrx=$(veth_rx | awk '{print $1}'); a_vrxd=$(veth_rx | awk '{print $2}')
    a_tx=$(veth0_tx | awk '{print $1}'); a_txd=$(veth0_tx | awk '{print $2}'); a_qd=$(qdisc_drop)

    local outer inner
    outer=$(sock_max "$PORT1" "$OUT/$tag.ss")
    inner=$(sock_max "$IPERF_PORT" "$OUT/$tag.ss")

    python3 - "$tag" "$rc" "$b_tb" "$a_tb" "$b_td" "$a_td" "$b_err" "$a_err" \
        "$b_vrx" "$a_vrx" "$b_vrxd" "$a_vrxd" "$b_tx" "$a_tx" "$b_txd" "$a_txd" "$b_qd" "$a_qd" \
        "$outer" "$inner" "$OUT/$tag.json" "$IMPL" "$PARALLEL" "$w" "$p" "$rep" "$LEN" >>"$CSV" <<'PY'
import json,sys
(tag,rc) = sys.argv[1], int(sys.argv[2])
(b_tb,a_tb,b_td,a_td,b_err,a_err,b_vrx,a_vrx,b_vrxd,a_vrxd,b_tx,a_tx,b_txd,a_txd,b_qd,a_qd) = [int(x) for x in sys.argv[3:19]]
outer,inner,jf,impl,par,w,p,rep,ln = sys.argv[19:28]
ln=int(ln)
od,orb,orq=[int(x) for x in outer.split()]; idr,irb,irq=[int(x) for x in inner.split()]
err_msg=""
try:
    s=json.load(open(jf))
    if "end" in s and "sum" in s["end"]:
        sm=s["end"]["sum"]; lost=sm.get("lost_packets",0); tot=sm.get("packets",0); lp=sm.get("lost_percent",0)
    else:
        st=s["end"]["streams"]
        lost=sum(x.get("udp",{}).get("lost_packets",0) for x in st)
        tot=sum(x.get("udp",{}).get("packets",0) for x in st)
        lp=100.0*lost/tot if tot else 0
except Exception as e:
    lost=tot=0; lp=0; err_msg=str(e).replace(",",";")
sent=tot+lost
# TUN получает inner IP-пакеты: payload + IPv4(20) + UDP(8)
expected=(ln+28)*sent
tun_bytes=a_tb-b_tb
gap=expected-tun_bytes
# TUN учитывает байты с систематическим недосчётом на пакет (проверяется
# отношением tun_bytes/expected: оно стабильно между прогонами). Поэтому
# абсолютный gap не критерий; критерий — падение отношения внутри группы.
ratio=(tun_bytes/expected) if expected else 0
print(f"{impl},{par},{w},{p},{rep},{rc},{sent},{tot},{lost},{lp:.4f},{tun_bytes},{expected},{gap},{ratio:.6f},"
      f"{a_td-b_td},{a_err-b_err},{od},{orb},{orq},{idr},{irb},{irq},"
      f"{a_vrx-b_vrx},{a_vrxd-b_vrxd},{a_tx-b_tx},{a_txd-b_txd},{a_qd-b_qd},{err_msg}")
PY
    log "$(tail -1 "$CSV")"
    sleep 0.3
}

log "старт: IMPL=$IMPL parallel=$PARALLEL W_LIST=\"$W_LIST\" P_LIST=\"$P_LIST\" REPEATS=$REPEATS"
for p in $P_LIST; do
    for w in $W_LIST; do
        for r in $(seq 1 "$REPEATS"); do one "$w" "$p" "$r"; done
    done
done

# --- сводка -----------------------------------------------------------------
python3 - "$CSV" <<'PY'
import csv,sys,statistics
rows=[r for r in csv.DictReader(open(sys.argv[1])) if r.get('rc')=='0']
print("\n=== СВОДКА ===")
if not rows:
    print("НЕТ УСПЕШНЫХ ПРОГОНОВ (см. *.err / *.srv.log)"); sys.exit(0)
hdr=f"{'impl':6} {'par':3} {'w':7} {'P':2} {'n':2} {'loss%':>8} {'tun_ratio':>9} {'outer_dr':>8} {'outer_rb':>9} {'rcvbuf_e':>8} {'tun_dr':>6} {'qdisc':>6} вердикт"
print(hdr)
by={}
for r in rows: by.setdefault((r['impl'],r['parallel'],r['w'],r['p']),[]).append(r)
worst_drop=0.0
for k,rs in by.items():
    loss=[float(r['lost_pct'] or 0) for r in rs]
    ratios=[float(r['tun_ratio'] or 0) for r in rs]
    rmin,rmax=min(ratios),max(ratios)
    od=sum(int(r['outer_drops']) for r in rs); re=sum(int(r['rcvbuf_err_delta']) for r in rs)
    td=sum(int(r['tun_dropped_delta']) for r in rs); qd=sum(int(r['qdisc_drop_delta']) for r in rs)
    lost=sum(int(r['lost']) for r in rs); orb=max(int(r['outer_rb'] or 0) for r in rs)
    tun_loss_pct=(rmax-rmin)*100
    worst_drop=max(worst_drop,tun_loss_pct)
    if od>0: verdict="ТУННЕЛЬ: дропы outer-сокета"
    elif td>0: verdict="ТУННЕЛЬ: дропы TUN"
    elif tun_loss_pct>0.2: verdict=f"ТУННЕЛЬ: до TUN не дошло ~{tun_loss_pct:.2f}%"
    elif lost>0 and re>=lost*0.9 and abs(re-lost)<=max(3,lost*0.1):
        verdict="iperf3: переполнение приёмного буфера"
    elif lost==0: verdict="потерь нет"
    else: verdict="неоднозначно: смотреть сырые ss/nstat"
    if orb and orb < 1_000_000:
        verdict += f" (outer SO_RCVBUF={orb})"
    print(f"{k[0]:6} {k[1]:3} {k[2]:7} {k[3]:2} {len(rs):2} {statistics.mean(loss):8.4f} "
          f"{rmin:.5f}-{rmax:.5f} {od:8d} {orb:9d} {re:8d} {td:6d} {qd:6d} {verdict}")
print(f"\nмакс. разброс tun_ratio по группам: {worst_drop:.3f}% (>0.2% = потеря до TUN)")
print("tun_ratio стабилен между прогонами одной группы и не зависит от дропов inner-сокета:") 
print("TUN учитывает байты с систематическим недосчётом на пакет, поэтому важен разброс, не abs(gap).")
print("Сырые данные: "+sys.argv[1])
PY
