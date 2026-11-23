#!/bin/bash
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../bench-lib.sh"

fails=0
total=0

check_eq() {
    local name=$1 want=$2 got=$3
    total=$((total + 1))
    if [ "$want" = "$got" ]; then
        echo "ok   $name"
    else
        echo "FAIL $name: want=[$want] got=[$got]"
        fails=$((fails + 1))
    fi
}

check_rc() {
    local name=$1 want=$2
    shift 2
    "$@" >/dev/null 2>&1
    local rc=$?
    total=$((total + 1))
    if [ "$rc" = "$want" ]; then
        echo "ok   $name (rc=$rc)"
    else
        echo "FAIL $name: want rc=$want got rc=$rc"
        fails=$((fails + 1))
    fi
}

check_contains() {
    local name=$1 needle=$2 haystack=$3
    total=$((total + 1))
    case "$haystack" in
        *"$needle"*) echo "ok   $name" ;;
        *)
            echo "FAIL $name: нет [$needle] в [$haystack]"
            fails=$((fails + 1))
            ;;
    esac
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

check_eq "cpu_mask 0-2" "7" "$(cpu_mask "0-2")"
check_eq "cpu_mask 0,3" "9" "$(cpu_mask "0,3")"
check_eq "cpu_mask 0-5" "3f" "$(cpu_mask "0-5")"
check_eq "cpu_mask 3" "8" "$(cpu_mask "3")"
check_eq "all_cpus_mask" "$(cpu_mask "0-$(( $(nproc) - 1 ))")" "$(all_cpus_mask)"

mkdir -p "$tmp/dirs/a" "$tmp/dirs/b"
: > "$tmp/file-a"
: > "$tmp/file-b"
check_eq "first_existing_dir первый" "$tmp/dirs/a" "$(first_existing_dir "$tmp/dirs/a" "$tmp/dirs/b")"
check_eq "first_existing_dir второй" "$tmp/dirs/b" "$(first_existing_dir "$tmp/missing" "$tmp/dirs/b")"
check_eq "first_existing_dir нет" "" "$(first_existing_dir "$tmp/missing")"
check_rc "first_existing_dir нет rc" 0 first_existing_dir "$tmp/missing"
check_eq "first_existing_dir файл не каталог" "" "$(first_existing_dir "$tmp/file-a")"
check_eq "first_existing_file первый" "$tmp/file-a" "$(first_existing_file "$tmp/file-a" "$tmp/file-b")"
check_eq "first_existing_file второй" "$tmp/file-b" "$(first_existing_file "$tmp/missing" "$tmp/file-b")"
check_eq "first_existing_file нет" "" "$(first_existing_file "$tmp/missing")"
check_rc "first_existing_file нет rc" 0 first_existing_file "$tmp/missing"
check_eq "first_existing_file каталог не файл" "" "$(first_existing_file "$tmp/dirs/a")"

cat > "$tmp/obf-full.conf" <<'EOF'
[Interface]
PrivateKey = x
S1 = 34
S4 = 28
Jc = 6
EOF
cat > "$tmp/obf-nos4.conf" <<'EOF'
[Interface]
PrivateKey = x
S1 = 34
EOF

check_eq "obf_s4 full" "28" "$(obf_s4 "$tmp/obf-full.conf")"
check_eq "obf_s4 нет ключа" "0" "$(obf_s4 "$tmp/obf-nos4.conf")"
check_eq "obf_s4 нет файла" "0" "$(obf_s4 "$tmp/missing.conf")"
check_eq "mtu_overhead obf=1" "108" "$(mtu_overhead "$tmp/obf-full.conf" 1 80)"
check_eq "mtu_overhead obf=0" "80" "$(mtu_overhead "$tmp/obf-full.conf" 0 80)"

check_contains "mtu_verdict 9000 ok" "ok underlay=9000" "$(mtu_verdict 1420 9000 108)"
check_rc "mtu_verdict 9000 rc" 0 mtu_verdict 1420 9000 108
check_contains "mtu_verdict 1500 fragment" "fragment underlay=1500" "$(mtu_verdict 1420 1500 108)"
check_rc "mtu_verdict 1500 rc" 1 mtu_verdict 1420 1500 108
check_rc "mtu_verdict 1500 tun 1380" 0 mtu_verdict 1380 1500 108
check_rc "mtu_verdict 1500 tun 1392" 0 mtu_verdict 1392 1500 108
check_rc "mtu_verdict 1500 tun 1393" 1 mtu_verdict 1393 1500 108
check_rc "mtu_verdict 1500 obf0 tun 1420" 0 mtu_verdict 1420 1500 80
check_rc "mtu_verdict 1500 obf0 tun 1421" 1 mtu_verdict 1421 1500 80

check_eq "rate_bps 1G" "1000000000" "$(rate_bps "1G")"
check_eq "rate_bps 500M" "500000000" "$(rate_bps "500M")"
check_eq "rate_bps 100k" "100000" "$(rate_bps "100k")"
check_eq "rate_bps 0" "0" "$(rate_bps "0")"
check_eq "rate_bps 1.5G" "1500000000" "$(rate_bps "1.5G")"
check_eq "rate_bps 2000000" "2000000" "$(rate_bps "2000000")"
check_rc "rate_bps мусор" 1 rate_bps "abc"
check_rc "rate_bps пусто" 1 rate_bps ""

check_eq "udp_stream_rate 1 поток" "1000000000" "$(udp_stream_rate 1000000000 1)"
check_eq "udp_stream_rate 10 потоков" "100000000" "$(udp_stream_rate 1000000000 10)"
check_eq "udp_stream_rate 100 потоков" "10000000" "$(udp_stream_rate 1000000000 100)"
check_eq "udp_stream_rate unlimited" "0" "$(udp_stream_rate 0 100)"
check_eq "udp_stream_rate минимум" "1000" "$(udp_stream_rate 1000 100)"

cat > "$tmp/snmp" <<'EOF'
Ip: Forwarding DefaultTTL InReceives InHdrErrors FragOKs FragFails FragCreates
Ip: 1 64 100 0 5 2 7
Icmp: InMsgs InErrors
Icmp: 1 0
EOF
check_eq "snmp_frag_counts_file" "5 2 7" "$(snmp_frag_counts_file "$tmp/snmp")"

check_eq "veth_rx_queue_count lo" "1" "$(veth_rx_queue_count lo)"
check_eq "veth_tx_queue_count lo" "1" "$(veth_tx_queue_count lo)"
check_contains "veth_queue_report lo rxq" "rxq=1" "$(veth_queue_report lo)"
check_rc "veth_enable_queues 1 очередь" 0 veth_enable_queues nosuchns nosuchdev 1 1

IDLE_LOAD_MAX=-1
if bench_busy_reasons "$$" >/dev/null 2>&1; then
    total=$((total + 1))
    echo "FAIL bench_busy_reasons: ожидалась занятость при IDLE_LOAD_MAX=-1"
    fails=$((fails + 1))
else
    total=$((total + 1))
    echo "ok   bench_busy_reasons load"
fi

cat > "$tmp/stat-before" <<'EOF'
cpu  100 0 100 800 0 0 0 0 0 0
cpu0 50 0 50 400 0 0 0 0 0 0
cpu1 50 0 50 400 0 0 0 0 0 0
intr 0
EOF
cat > "$tmp/stat-after" <<'EOF'
cpu  200 0 200 1600 0 0 0 0 0 0
cpu0 150 0 150 700 0 0 0 0 0 0
cpu1 100 0 100 800 0 0 0 0 0 0
intr 0
EOF
cat > "$tmp/stat-hot-before" <<'EOF'
cpu0 50 0 50 900 0 0 0 0 0 0
EOF
cat > "$tmp/stat-hot-after" <<'EOF'
cpu0 148 0 50 902 0 0 0 0 0 0
EOF

check_eq "proc_stat_cpu_lines только cpuN" "2" "$(proc_stat_cpu_lines "$tmp/stat-before" | wc -l)"
check_eq "proc_stat_cpu_lines первая строка" "cpu0 50 0 50 400 0 0 0 0 0 0" "$(proc_stat_cpu_lines "$tmp/stat-before" | head -1)"
check_eq "proc_stat_snapshot" "$(proc_stat_cpu_lines "$tmp/stat-before")" "$(proc_stat_snapshot "$tmp/stat-snap" "$tmp/stat-before"; cat "$tmp/stat-snap")"
check_eq "cpu_busy_summary 40/20" "per_cpu=40,20 hot_cpus=0 total=30" "$(cpu_busy_summary "$tmp/stat-before" "$tmp/stat-after" 80)"
check_eq "cpu_busy_summary hot" "per_cpu=98 hot_cpus=1 total=98" "$(cpu_busy_summary "$tmp/stat-hot-before" "$tmp/stat-hot-after" 80)"
check_eq "cpu_busy_summary порог 99" "per_cpu=98 hot_cpus=0 total=98" "$(cpu_busy_summary "$tmp/stat-hot-before" "$tmp/stat-hot-after" 99)"
check_eq "cpu_busy_summary без изменения" "per_cpu=0,0 hot_cpus=0 total=0" "$(cpu_busy_summary "$tmp/stat-before" "$tmp/stat-before" 80)"
check_eq "cpu_busy_summary пустой вход" "per_cpu=- hot_cpus=0 total=0" "$(cpu_busy_summary /dev/null /dev/null 80)"
proc_stat_snapshot "$tmp/real-a"
sleep 0.1
proc_stat_snapshot "$tmp/real-b"
check_eq "cpu_busy_summary реальный /proc/stat" "ok" "$(cpu_busy_summary "$tmp/real-a" "$tmp/real-b" 80 | awk '{ if ($0 ~ /^per_cpu=[0-9]+(,[0-9]+)* hot_cpus=[0-9]+ total=[0-9]+$/) print "ok"; else print $0 }')"

plan_out=$(PLAN_ONLY=1 FORCE=1 IMPL_LIST="" RESULT="$tmp/plan.csv" bash "$HERE/../bench.sh" 2>&1)
plan_rc=$?
check_eq "bench.sh PLAN_ONLY rc" "0" "$plan_rc"
check_contains "bench.sh PLAN_ONLY RESULTS" "RESULTS=$tmp/plan.csv" "$plan_out"
check_contains "bench.sh PLAN_ONLY PATHS" "PATHS bench_dir=" "$plan_out"
check_eq "bench.sh PLAN_ONLY csv header" "impl,mode,proto,conns,loss,obf,peers,mbit,extra,run,repeat,lost_percent,udp_rate,udp_mode,streams,frag,cpu_hot,cpu_total,fec" "$(head -1 "$tmp/plan.csv")"
legacy_root="/root/""umbrawg"
if printf '%s' "$plan_out" | grep -qF "$legacy_root"; then
    total=$((total + 1))
    echo "FAIL bench.sh PLAN_ONLY без жёстких путей: в выводе путь старого стенда"
    fails=$((fails + 1))
else
    total=$((total + 1))
    echo "ok   bench.sh PLAN_ONLY без жёстких путей"
fi

cat > "$tmp/obf-template.conf" <<'EOF'
# профиль: секретов нет
[Interface]
PrivateKey = <PRIVATE_KEY>
ListenPort = 51820
S1 = 34
HeaderProtectionKey = <HEADER_PROTECTION_KEY>
ContentPaddingAddition = 51-197

[Peer]
PublicKey = <PEER_PUBLIC_KEY>
AllowedIPs = 10.9.0.0/24
EOF

obf_out=$(obf_block_from_conf "$tmp/obf-template.conf" printf 'KEYGEN=\n')
check_eq "obf_block_from_conf убирает PrivateKey" "0" "$(printf '%s\n' "$obf_out" | grep -c 'PRIVATE_KEY' || true)"
check_eq "obf_block_from_conf убирает ListenPort" "0" "$(printf '%s\n' "$obf_out" | grep -c '^ListenPort' || true)"
check_eq "obf_block_from_conf убирает секцию Peer" "0" "$(printf '%s\n' "$obf_out" | grep -cE '^(\[Peer\]|PublicKey|AllowedIPs)' || true)"
check_eq "obf_block_from_conf убирает комментарии" "0" "$(printf '%s\n' "$obf_out" | grep -c '^#' || true)"
check_contains "obf_block_from_conf подставляет HeaderProtectionKey" "HeaderProtectionKey = KEYGEN=" "$obf_out"
check_eq "obf_block_from_conf один HeaderProtectionKey" "1" "$(printf '%s\n' "$obf_out" | grep -c '^HeaderProtectionKey' || true)"
check_contains "obf_block_from_conf сохраняет профиль" "S1 = 34" "$obf_out"
check_eq "obf_block_from_conf нет файла" "" "$(obf_block_from_conf "$tmp/no-such.conf" printf 'KEYGEN=\n')"
check_rc "obf_block_from_conf ошибка генератора" 1 obf_block_from_conf "$tmp/obf-template.conf" false
check_rc "obf_block_from_conf пустой генератор" 1 obf_block_from_conf "$tmp/obf-template.conf" true

echo "---"
echo "тестов: $total, провалов: $fails"
[ "$fails" = "0" ]
