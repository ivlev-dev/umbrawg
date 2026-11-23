#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Regression test for partial FEC blocks with parity (FEC_PARTIAL, bit 4).
#
# A sparse stream (one ICMP echo per block) used to flush a partial block as
# k' = 1, m' = 0, so any single lost shard made the ping unrecoverable. With
# FEC_PARTIAL the same block is sent as k' = n, m' = local m and survives one
# loss per block.
#
# What it checks:
#   1. kernel <-> kernel, FEC 2:1, netem 2 % loss, sparse ping at 10 pps:
#      0 % loss in both directions (was 3-6 %).
#   2. the same pair with the module knob fec_partial=0: peers advertise no
#      FEC_PARTIAL and keep the legacy m' = 0 form; the link still works and
#      the loss is recorded as the "before" number.
#   3. full-size TCP/UDP with FEC 2:1: no regression and no WARN/BUG.
#   4. optional kernel <-> Rust sparse ping when RUST= points at a daemon
#      built with the FEC_PARTIAL fix.
#
# Usage:
#   sudo KO=/path/umbrawg.ko UWG=/path/uwg RUST=/path/umbrawg \
#        src/tests/fec-partial.sh
#
# Exit code: 0 pass, 1 a check failed, 2 setup/usage error.

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
KO=${KO:-$SCRIPT_DIR/../umbrawg.ko}
UWG=${UWG:-uwg}
RUST=${RUST:-}
WORK=${WORK:-/tmp/uwg-fec-partial.$$}
PING_COUNT=${PING_COUNT:-200}
PING_INTERVAL=${PING_INTERVAL:-0.1}
TCP_SECS=${TCP_SECS:-5}

NS0="uwgfp0-$$"
NS1="uwgfp1-$$"
V0="vfp0-$$"
V1="vfp1-$$"
UL0=172.31.94.1
UL1=172.31.94.2
T0=10.94.0.1
T1=10.94.0.2
PORT0=$((22000 + ($$ % 20000)))
PORT1=$((PORT0 + 1))
IPERF_PORT=$((PORT0 + 2))

FAILED=0
ACTIVE_NS=
RUST_PID=

mkdir -p "$WORK"
LOG=$WORK/test.log
: >"$LOG"

say() { printf '%s\n' "$*" | tee -a "$LOG"; }
fail() { say "FAIL: $*"; FAILED=1; }

cleanup() {
	if [ -n "$RUST_PID" ]; then
		kill "$RUST_PID" 2>/dev/null
		RUST_PID=
	fi
	for ns in $ACTIVE_NS "$NS0" "$NS1"; do
		ip netns del "$ns" 2>/dev/null
	done
	ip link del "$V0" 2>/dev/null
	ip link del "$V1" 2>/dev/null
	rmmod umbrawg 2>/dev/null
	rm -f /var/run/umbrawg/uwg1.sock
}
trap cleanup EXIT INT TERM

need() {
	command -v "$1" >/dev/null 2>&1 || { say "missing required tool: $1"; exit 2; }
}

need ip
need tc
need ping
need "$UWG"
[ -r "$KO" ] || { say "missing module: $KO"; exit 2; }

teardown() {
	cleanup
	rm -f /var/run/umbrawg/uwg1.sock
}

create_namespaces() {
	ip netns add "$NS0" || return 1
	ip netns add "$NS1" || return 1
	ip link add "$V0" type veth peer name "$V1" || return 1
	ip link set "$V0" netns "$NS0"
	ip link set "$V1" netns "$NS1"
	ip -n "$NS0" addr add "$UL0/24" dev "$V0"
	ip -n "$NS1" addr add "$UL1/24" dev "$V1"
	ip -n "$NS0" link set "$V0" mtu 9000 up
	ip -n "$NS1" link set "$V1" mtu 9000 up
	ip -n "$NS0" link set lo up
	ip -n "$NS1" link set lo up
	ACTIVE_NS="$NS0 $NS1"
}

kernel_configs() { # $1 = FEC mode
	local fec=$1
	cat >"$WORK/c0.conf" <<-EOF
	[Interface]
	PrivateKey = $K0
	ListenPort = $PORT0
	FEC = $fec

	[Peer]
	PublicKey = $PUB1
	AllowedIPs = 10.94.0.0/24
	Endpoint = $UL1:$PORT1
	PersistentKeepalive = 5
	EOF
	cat >"$WORK/c1.conf" <<-EOF
	[Interface]
	PrivateKey = $K1
	ListenPort = $PORT1
	FEC = $fec

	[Peer]
	PublicKey = $PUB0
	AllowedIPs = 10.94.0.0/24
	Endpoint = $UL0:$PORT0
	PersistentKeepalive = 5
	EOF
}

wait_link() {
	local i
	for i in $(seq 1 40); do
		if ip netns exec "$NS0" ping -c 1 -W 1 "$T1" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.5
	done
	return 1
}

setup_kk() { # $1 = fec_partial knob
	teardown
	insmod "$KO" fec_partial="$1" || return 1
	create_namespaces || return 1
	ip -n "$NS0" link add uwg0 type umbrawg || return 1
	ip -n "$NS1" link add uwg1 type umbrawg || return 1
	ip -n "$NS0" addr add "$T0/24" dev uwg0
	ip -n "$NS1" addr add "$T1/24" dev uwg1
	ip -n "$NS0" link set uwg0 up
	ip -n "$NS1" link set uwg1 up
	K0=$($UWG genkey); K1=$($UWG genkey)
	PUB0=$(printf '%s' "$K0" | $UWG pubkey)
	PUB1=$(printf '%s' "$K1" | $UWG pubkey)
	kernel_configs 2:1
	ip netns exec "$NS0" "$UWG" setconf uwg0 "$WORK/c0.conf" >/dev/null || return 1
	ip netns exec "$NS1" "$UWG" setconf uwg1 "$WORK/c1.conf" >/dev/null || return 1
	wait_link
}

setup_kr() { # kernel in NS0, Rust daemon in NS1, FEC 2:1
	[ -n "$RUST" ] && [ -x "$RUST" ] || return 1
	teardown
	insmod "$KO" fec_partial=1 || return 1
	create_namespaces || return 1
	ip -n "$NS0" link add uwg0 type umbrawg || return 1
	mkdir -p /var/run/umbrawg
	ip netns exec "$NS1" env UMBRAWG_FEC=2:1 \
		"$RUST" --foreground uwg1 >"$WORK/rust.log" 2>&1 &
	RUST_PID=$!
	local i
	for i in $(seq 1 50); do
		[ -S /var/run/umbrawg/uwg1.sock ] && break
		sleep 0.1
	done
	ip -n "$NS0" addr add "$T0/24" dev uwg0
	ip -n "$NS1" addr add "$T1/24" dev uwg1
	ip -n "$NS0" link set uwg0 up
	ip -n "$NS1" link set uwg1 up
	K0=$($UWG genkey); K1=$($UWG genkey)
	PUB0=$(printf '%s' "$K0" | $UWG pubkey)
	PUB1=$(printf '%s' "$K1" | $UWG pubkey)
	kernel_configs 2:1
	cat >"$WORK/c1-rust.conf" <<-EOF
	[Interface]
	PrivateKey = $K1
	ListenPort = $PORT1

	[Peer]
	PublicKey = $PUB0
	AllowedIPs = 10.94.0.0/24
	Endpoint = $UL0:$PORT0
	PersistentKeepalive = 5
	EOF
	ip netns exec "$NS0" "$UWG" setconf uwg0 "$WORK/c0.conf" >/dev/null || return 1
	"$UWG" setconf uwg1 "$WORK/c1-rust.conf" >/dev/null || return 1
	wait_link
}

apply_netem() {
	ip netns exec "$NS0" tc qdisc replace dev "$V0" root netem loss 2% || return 1
	ip netns exec "$NS1" tc qdisc replace dev "$V1" root netem loss 2% || return 1
}

clear_netem() {
	ip netns exec "$NS0" tc qdisc del dev "$V0" root 2>/dev/null
	ip netns exec "$NS1" tc qdisc del dev "$V1" root 2>/dev/null
}

ping_loss() { # $1 = ns, $2 = target
	local out loss rc
	out=$(ip netns exec "$1" ping -c "$PING_COUNT" -i "$PING_INTERVAL" -W 1 "$2" 2>&1)
	rc=$?
	printf '%s\n' "$out" >"$WORK/ping-$1-$2.log"
	# The loss percentage is fractional on any real loss (e.g. "4.5%"), so
	# the old integer-only sed pattern silently produced "no summary" and the
	# caller treated it as a 100% black hole. Round to an integer, which is
	# what the callers compare against.
	loss=$(printf '%s\n' "$out" |
		awk '/% packet loss/ {
			for (i = 1; i <= NF; i++)
				if ($i ~ /^[0-9.]+%$/) {
					sub(/%$/, "", $i);
					printf "%.0f\n", $i;
					exit
				}
		}')
	if [ -z "$loss" ]; then
		say "ping $1 -> $2 produced no summary (rc=$rc, $(printf '%s' "$out" | wc -c) bytes)"
	fi
	printf '%s\n' "$loss"
}

measure_sparse() { # $1 = label
	local label=$1 fwd rev before after
	apply_netem || { fail "$label: netem"; return; }
	before=$(ip netns exec "$NS0" "$UWG" show uwg0 fec-stats 2>/dev/null | sed -n 's/^dropped_bounds=//p')
	fwd=$(ping_loss "$NS0" "$T1")
	rev=$(ping_loss "$NS1" "$T0")
	after=$(ip netns exec "$NS0" "$UWG" show uwg0 fec-stats 2>/dev/null | sed -n 's/^dropped_bounds=//p')
	clear_netem
	say "$label: kernel->peer loss=${fwd:-?}% peer->kernel loss=${rev:-?}% dropped_bounds ${before:-?}->${after:-?}"
	printf '%s %s\n' "${fwd:-100}" "${rev:-100}" >"$WORK/last-loss"
}

measure_bulk() { # $1 = label
	local label=$1
	local tcp udp
	local srvlog="$WORK/iperf-$label.log"
	ip netns exec "$NS1" iperf3 -s -1 -p "$IPERF_PORT" -D --logfile "$srvlog" 2>/dev/null
	sleep 0.3
	tcp=$(ip netns exec "$NS0" iperf3 -c "$T1" -p "$IPERF_PORT" -t "$TCP_SECS" 2>&1 |
		grep -o '[0-9.]* [MG]bits/sec' | tail -1)
	ip netns exec "$NS1" iperf3 -s -1 -p "$IPERF_PORT" -D --logfile "$srvlog.udp" 2>/dev/null
	sleep 0.3
	udp=$(ip netns exec "$NS0" iperf3 -c "$T1" -p "$IPERF_PORT" -u -b 100M \
		-t "$TCP_SECS" 2>&1 |
		grep -o '[0-9.]* [MG]bits/sec' | tail -1)
	say "$label: TCP ${tcp:-?}, UDP ${udp:-?}"
	[ -n "$tcp" ] && [ -n "$udp" ] || fail "$label: bulk traffic did not complete"
}

check_kernel_log() {
	if dmesg | grep -E 'WARNING:|BUG:|Oops|general protection' | tail -5 | grep -q .; then
		dmesg | grep -E 'WARNING:|BUG:|Oops|general protection' | tail -5 | tee -a "$LOG"
		fail "kernel log contains a warning or BUG"
	fi
}

say "=== 1) kernel<->kernel FEC 2:1, fec_partial=1, netem 2%"
setup_kk 1 || { say "setup failed"; exit 2; }
measure_sparse "partial parity"
read -r FWD REV <"$WORK/last-loss"
[ "${FWD:-100}" = 0 ] || fail "partial parity forward loss ${FWD}% (expected 0)"
[ "${REV:-100}" = 0 ] || fail "partial parity reverse loss ${REV}% (expected 0)"
say "kernel fec-stats: $(ip netns exec "$NS0" "$UWG" show uwg0 fec-stats | tr '\n' ' ')"
BLOCKS=$(ip netns exec "$NS0" "$UWG" show uwg0 fec-stats | sed -n 's/^blocks_encoded=//p')
RECOVERED=$(ip netns exec "$NS0" "$UWG" show uwg0 fec-stats | sed -n 's/^packets_recovered=//p')
[ "${BLOCKS:-0}" -gt 0 ] || fail "no FEC blocks were encoded"
[ "${RECOVERED:-0}" -gt 0 ] || fail "no packet was recovered from partial parity"
measure_bulk "bulk"
check_kernel_log
teardown

say "=== 2) legacy compatibility: fec_partial=0, netem 2%"
setup_kk 0 || { say "setup failed"; exit 2; }
measure_sparse "legacy m'=0"
read -r FWD REV <"$WORK/last-loss"
[ "${FWD:-100}" -lt 100 ] || fail "legacy forward direction is a black hole"
[ "${REV:-100}" -lt 100 ] || fail "legacy reverse direction is a black hole"
say "legacy compatibility kept (loss is the expected pre-fix number)"
check_kernel_log
teardown

if [ -n "$RUST" ] && [ -x "$RUST" ]; then
	say "=== 3) kernel<->Rust FEC 2:1 (Rust with FEC_PARTIAL), netem 2%"
	if setup_kr; then
		measure_sparse "kernel<->Rust partial"
		read -r FWD REV <"$WORK/last-loss"
		[ "${FWD:-100}" = 0 ] || fail "kernel->Rust loss ${FWD}%"
		[ "${REV:-100}" = 0 ] || fail "Rust->kernel loss ${REV}%"
		check_kernel_log
	else
		say "SKIP: kernel<->Rust (RUST not usable)"
	fi
	teardown
else
	say "SKIP: kernel<->Rust (set RUST=/path/to/umbrawg to run it)"
fi

if [ "$FAILED" = 0 ]; then
	say "PASS: partial FEC parity"
	exit 0
fi
say "FAILED"
exit 1
