#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Харнесс профилирования разрыва kernel↔Rust на живом прогоне стенда.
#
# Трафик НЕ создаёт: цепляется к уже идущему прогону (bench/run-multi2.sh),
# снимает perf/bpftrace/счётчики и складывает всё в один каталог.
#
#   perf-gap.sh collect [SECONDS] [TAG]   # perf record + stat + bpftrace + снимки
#   perf-gap.sh light   [SECONDS] [TAG]   # только bpftrace + снимки (дешевле)
#   perf-gap.sh snap    [TAG]             # один снимок счётчиков
#   perf-gap.sh report  DIR               # отчёты по готовому perf.data
#
# Переменные:
#   OUT       корень артефактов (default /root/perf-gap)
#   PERF_FREQ частота perf record (default 999)
#   KO        путь к umbrawg.ko: добавляется в perf buildid-cache, чтобы
#             символы модуля резолвились и после выгрузки
#
# Пример:
#   bash perf-gap.sh collect 20 kernel-p5
#   bash perf-gap.sh report /root/perf-gap/20261122-190000-kernel-p5
#
# Что смотреть (см. docs/GAP-VS-RUST.md, §6):
#   symbols.txt  — доля __udp_gso_segment/skb_segment/__alloc_skb (R1),
#                  uwg_packet_gso_alloc/skb_copy_bits (R2),
#                  chacha/lib-sg vs uwg_aead_* (R4), queue_work_on (R3).
#   bpftrace.txt — счётчики по стадиям, гистограммы латентностей, softirq.
#   softnet.txt  — time_squeeze/dropped по CPU.

set -u

usage() {
	sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
}

# Отчёты по готовому perf.data (не требует запущенного прогона).
do_report() {
	local dir=$1
	if [ ! -f "$dir/perf.data" ]; then
		echo "в $dir нет perf.data" >&2
		return 1
	fi
	perf report -i "$dir/perf.data" --stdio --no-children \
		--sort comm,dso,symbol --percent-limit 0.2 \
		> "$dir/symbols.txt" 2>"$dir/symbols.err"
	perf report -i "$dir/perf.data" --stdio --no-children \
		--sort comm --percent-limit 0.2 > "$dir/comm.txt" 2>/dev/null
	perf report -i "$dir/perf.data" --stdio --no-children \
		--sort dso --percent-limit 0.2 > "$dir/dso.txt" 2>/dev/null
	for sym in uwg_packet_receive uwg_packet_rx_poll \
		   uwg_packet_create_data_done uwg_packet_encrypt_worker \
		   uwg_packet_tx_worker; do
		perf annotate -i "$dir/perf.data" -s "$sym" --stdio \
			> "$dir/annotate-$sym.txt" 2>/dev/null
	done
	if command -v stackcollapse-perf.pl >/dev/null &&
	   command -v flamegraph.pl >/dev/null; then
		perf script -i "$dir/perf.data" 2>/dev/null |
			stackcollapse-perf.pl > "$dir/perf.folded" 2>/dev/null
		flamegraph.pl --title "$(basename "$dir")" \
			"$dir/perf.folded" > "$dir/flamegraph.svg" 2>/dev/null
	fi
	echo "отчёты: $dir/{symbols,comm,dso}.txt, annotate-*.txt, flamegraph.svg"
	if [ -f "$dir/softnet-before.txt" ] && [ -f "$dir/softnet-after.txt" ]; then
		echo "--- softnet Δ (processed / dropped / time_squeeze)"
		awk 'FNR==1 {next}
		     NR==FNR { b[$1] = $2" "$3" "$4; next }
		     { p = b[$1]; split(p, a, " ");
		       printf "cpu%s processed=%d dropped=%d time_squeeze=%d\n",
			      $1, $2 - a[1], $3 - a[2], $4 - a[3] }' \
			"$dir/softnet-before.txt" "$dir/softnet-after.txt" \
			> "$dir/softnet-delta.txt"
		cat "$dir/softnet-delta.txt"
	fi
}

# ---------------------------------------------------------------- аргументы

MODE=${1:-collect}
SECS=${2:-15}
TAG=${3:-run}
[ "$MODE" = "snap" ] && TAG=${2:-run}
OUT_ROOT=${OUT:-/root/perf-gap}
PERF_FREQ=${PERF_FREQ:-999}
[ "$MODE" = "snap" ] && SECS=0

case "$MODE" in
	collect|light|snap|report) ;;
	*)
		usage
		;;
esac

if ! command -v perf >/dev/null; then
	echo "perf не найден" >&2
	exit 1
fi

if [ -n "${KO:-}" ] && [ -f "$KO" ]; then
	perf buildid-cache -a "$KO" 2>/dev/null || true
fi

STAMP=$(date +%Y%m%d-%H%M%S)
DIR="$OUT_ROOT/$STAMP-$TAG"
mkdir -p "$DIR"

exec 9>"$OUT_ROOT/.perf-gap.lock" 2>/dev/null || true
if command -v flock >/dev/null && ! flock -n 9; then
	echo "другой perf-gap уже работает" >&2
	exit 1
fi

log() { printf '[%s] %s\n' "$(date +%T)" "$*" | tee -a "$DIR/run.log"; }

# ---------------------------------------------------------------- утилиты

kallsyms_has() {
	awk -v s="$1" '$3==s {found=1} END{exit !found}' /proc/kallsyms
}

module_loaded() {
	lsmod | awk '$1=="umbrawg"{f=1} END{exit !f}'
}

# strtonum есть не во всех awk (mawk), поэтому hex парсим вручную.
softnet_dump() {
	local out=$1
	{
		echo "# cpu processed dropped time_squeeze backlog_len"
		awk '
			function h2d(h,   i, c, v) {
				v = 0; h = tolower(h)
				for (i = 1; i <= length(h); i++) {
					c = index("0123456789abcdef", substr(h, i, 1)) - 1
					v = v * 16 + c
				}
				return v
			}
			{ printf "%d %d %d %d %d\n", NR - 1, h2d($1), h2d($2), h2d($3), h2d($12) }
		' /proc/net/softnet_stat
	} > "$out"
}

snapshot() {
	local tag=$1
	softnet_dump "$DIR/softnet-$tag.txt"
	cp /proc/softirqs "$DIR/softirqs-$tag.txt" 2>/dev/null || true
	cp /proc/interrupts "$DIR/interrupts-$tag.txt" 2>/dev/null || true
	cp /proc/net/udp "$DIR/udp-$tag.txt" 2>/dev/null || true
	cp /proc/net/snmp "$DIR/snmp-$tag.txt" 2>/dev/null || true
	nstat -az > "$DIR/nstat-$tag.txt" 2>/dev/null || true
	{
		ip -br link 2>/dev/null
		echo "--- статистика устройств"
		for dev in $(ip -br link 2>/dev/null |
			     awk '$1 ~ /^(bveth|sv|uwg|wg|amnezia)/ {print $1}'); do
			echo "## $dev"
			timeout 2 ethtool -S "$dev" 2>/dev/null | head -40
		done
		echo "--- ss -ti"
		timeout 3 ss -ti state established 2>/dev/null | head -40
		echo "--- slab"
		timeout 5 slabtop -s c -o 2>/dev/null | grep -Ei "skbuff|kmalloc" | head -15
	} > "$DIR/state-$tag.txt"
}

# ---------------------------------------------------------------- bpftrace

# Таблица: "проба|тело". Символы, которых нет в kallsyms, пропускаются:
# имена в 7.3.x разъезжаются (kfree_skb → __kfree_skb, napi_gro_receive
# инлайнится, process_one_work → process_scheduled_works и т.д.).
bt_probes() {
	cat <<'EOF'
kprobe:__udp_gso_segment|@stage["rx_gso_split"] = count();
kprobe:udp_gro_receive|@stage["rx_gro"] = count();
kprobe:skb_segment|@stage["skb_segment"] = count();
kprobe:dev_gro_receive|@stage["gro_receive"] = count();
kprobe:netif_receive_skb|@stage["netif_receive_skb"] = count();
kprobe:ip_rcv|@stage["ip_rcv"] = count();
kprobe:udp_sendmsg|@stage["udp_sendmsg"] = count();
kprobe:udp_tunnel_xmit_skb|@stage["udp_tunnel_xmit"] = count();
kprobe:__alloc_skb|@alloc[comm] = count();
kprobe:__kfree_skb|@free[comm] = count();
kprobe:skb_release_data|@stage["skb_release_data"] = count();
kprobe:skb_copy_bits|@stage["skb_copy_bits"] = count();
kprobe:skb_cow_data|@stage["skb_cow_data"] = count();
kprobe:pskb_expand_head|@stage["pskb_expand_head"] = count();
kprobe:queue_work_on|@stage["queue_work_on"] = count();
kprobe:try_to_wake_up|@stage["try_to_wake_up"] = count();
kprobe:mod_timer|@stage["mod_timer"] = count();
kprobe:timer_reduce|@stage["timer_reduce"] = count();
kprobe:chacha20poly1305_encrypt_sg_inplace|@cipher["lib_chacha_enc_sg"] = count();
kprobe:chacha20poly1305_decrypt_sg_inplace|@cipher["lib_chacha_dec_sg"] = count();
kprobe:uwg_packet_receive|@stage["uwg_rx"] = count(); @rx_t[tid] = nsecs;
kretprobe:uwg_packet_receive /@rx_t[tid]/|@rx_ns = hist(nsecs - @rx_t[tid]); delete(@rx_t[tid]);
kprobe:uwg_packet_rx_poll|@stage["uwg_rx_poll"] = count(); @poll_t[tid] = nsecs;
kretprobe:uwg_packet_rx_poll /@poll_t[tid]/|@poll_ns = hist(nsecs - @poll_t[tid]); delete(@poll_t[tid]);
kprobe:uwg_packet_send_staged_packets|@stage["uwg_tx_stage"] = count(); @st_t[tid] = nsecs;
kretprobe:uwg_packet_send_staged_packets /@st_t[tid]/|@stage_ns = hist(nsecs - @st_t[tid]); delete(@st_t[tid]);
kprobe:uwg_packet_gso_alloc|@stage["uwg_gso_alloc"] = count();
kprobe:uwg_socket_send_skb_to_peer|@stage["uwg_underlay_skb"] = count();
kprobe:uwg_aead_encrypt|@cipher["uwg_aead_enc"] = count();
kprobe:uwg_aead_decrypt|@cipher["uwg_aead_dec"] = count();
kprobe:uwg_packet_encrypt_worker|@crypt_t[tid] = nsecs;
kretprobe:uwg_packet_encrypt_worker /@crypt_t[tid]/|@enc_busy_ns = hist(nsecs - @crypt_t[tid]); delete(@crypt_t[tid]);
kprobe:uwg_packet_decrypt_worker|@decrypt_t[tid] = nsecs;
kretprobe:uwg_packet_decrypt_worker /@decrypt_t[tid]/|@dec_busy_ns = hist(nsecs - @decrypt_t[tid]); delete(@decrypt_t[tid]);
tracepoint:irq:softirq_entry|@sirq_start[args->vec, cpu] = nsecs;
tracepoint:irq:softirq_exit|@sirq_ns[args->vec] = sum(nsecs - @sirq_start[args->vec, cpu]); delete(@sirq_start[args->vec, cpu]);
EOF
}

build_bt() {
	local out=$1 spec probe body base
	local n=0
	{
		echo 'BEGIN { printf("perf-gap bpftrace start\n"); }'
		while IFS='|' read -r spec body; do
			[ -n "$spec" ] || continue
			probe=${spec%% *}
			base=${probe#*:}
			case "$probe" in
				tracepoint:*) ;;
				*) kallsyms_has "$base" || continue ;;
			esac
			printf '%s { %s }\n' "$spec" "$body"
			n=$((n + 1))
		done < <(bt_probes)
		echo 'END { clear(@rx_t); clear(@poll_t); clear(@st_t); clear(@crypt_t); clear(@decrypt_t); }'
	} > "$out"
}

run_bpftrace() {
	local secs=$1
	if ! command -v bpftrace >/dev/null; then
		log "bpftrace не найден — пропускаю"
		return
	fi
	if ! module_loaded; then
		log "модуль umbrawg не загружен: uwg_* пробы будут пропущены"
	fi
	build_bt "$DIR/probes.bt"
	log "bpftrace: $(grep -c ' {' "$DIR/probes.bt") проб, ${secs}s"
	timeout -s INT "$secs" bpftrace -f text -o "$DIR/bpftrace.txt" \
		"$DIR/probes.bt" >"$DIR/bpftrace.log" 2>&1
	log "bpftrace готов: $DIR/bpftrace.txt"
}

# ---------------------------------------------------------------- отчёты

# ---------------------------------------------------------------- режимы

log "режим=$MODE tag=$TAG каталог=$DIR"
log "uname=$(uname -r) cpus=$(nproc) модуль=$(module_loaded && echo да || echo нет)"

case "$MODE" in
report)
	[ -n "${2:-}" ] || usage
	do_report "$2"
	;;
snap)
	snapshot before
	log "снимок: $DIR/state-before.txt"
	;;
light)
	snapshot before
	run_bpftrace "$SECS"
	snapshot after
	;;
collect)
	snapshot before
	vmstat 1 "$SECS" > "$DIR/vmstat.txt" 2>/dev/null &
	VM_PID=$!
	run_bpftrace "$SECS" &
	BT_PID=$!
	log "perf stat ${SECS}s"
	perf stat -a -o "$DIR/perf-stat.txt" \
		-e cycles,instructions,branches,branch-misses,cache-misses,cache-references,context-switches,cpu-migrations,page-faults \
		-- sleep "$SECS" 2>>"$DIR/perf-stat.err"
	log "perf record ${SECS}s @ ${PERF_FREQ}Hz"
	perf record -a -g -F "$PERF_FREQ" -o "$DIR/perf.data" \
		-- sleep "$SECS" 2>"$DIR/perf-record.err"
	wait "$BT_PID" 2>/dev/null || true
	wait "$VM_PID" 2>/dev/null || true
	snapshot after
	log "готово: $DIR"
	log "отчёты: $0 report $DIR"
	;;
esac
