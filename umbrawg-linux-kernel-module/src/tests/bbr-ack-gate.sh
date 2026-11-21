#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# BBR must not pace, gate or account traffic for a peer that has not
# confirmed ACK in CAPS. The Rust implementation gates on the same bit; this
# test covers the mixed case that exposed the bug: kernel BBR=on against a
# peer that runs with BBR and FEC both off and therefore never advertises ACK.
#
# Checks:
#   1. kernel(BBR=on) <-> Rust(BBR=off, FEC=off): TCP flows, and kernel
#      bbr-stats reports inflight=0 and pacing_rate=0 (controller inactive).
#   2. kernel(BBR=on) <-> kernel(BBR=on): normal peer with ACK still paces
#      and tracks inflight.
#   3. kernel(BBR=off) throughput is the baseline; BBR=on must not be worse
#      than 70 % of it.
#
# Usage:
#   sudo KO=/path/umbrawg.ko UWG=/path/uwg RUST=/path/umbrawg \
#        src/tests/bbr-ack-gate.sh
#
# Exit code: 0 pass, 1 a check failed, 2 setup/usage error.

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
KO=${KO:-$SCRIPT_DIR/../umbrawg.ko}
UWG=${UWG:-uwg}
RUST=${RUST:-}
WORK=${WORK:-/tmp/uwg-bbr-ack.$$}
TCP_SECS=${TCP_SECS:-6}

NS0="uwgba0-$$"
NS1="uwgba1-$$"
V0="vba0-$$"
V1="vba1-$$"
UL0=172.31.95.1
UL1=172.31.95.2
T0=10.95.0.1
T1=10.95.0.2
PORT0=$((24000 + ($$ % 20000)))
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
	rm -f /var/run/umbrawg/uwg1.sock
	rmmod umbrawg 2>/dev/null
}
trap cleanup EXIT INT TERM

need() { command -v "$1" >/dev/null 2>&1 || { say "missing required tool: $1"; exit 2; }; }
need ip
need ping
need iperf3
need "$UWG"
[ -r "$KO" ] || { say "missing module: $KO"; exit 2; }

teardown() { cleanup; }

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

wait_link() {
	local i
	for i in $(seq 1 40); do
		ip netns exec "$NS0" ping -c 1 -W 1 "$T1" >/dev/null 2>&1 && return 0
		sleep 0.5
	done
	return 1
}

configs() { # $1 = kernel BBR value
	local bbr=$1
	cat >"$WORK/c0.conf" <<-EOF
	[Interface]
	PrivateKey = $K0
	ListenPort = $PORT0
	BBR = $bbr

	[Peer]
	PublicKey = $PUB1
	AllowedIPs = 10.95.0.0/24
	Endpoint = $UL1:$PORT1
	PersistentKeepalive = 5
	EOF
	cat >"$WORK/c1.conf" <<-EOF
	[Interface]
	PrivateKey = $K1
	ListenPort = $PORT1
	BBR = $bbr

	[Peer]
	PublicKey = $PUB0
	AllowedIPs = 10.95.0.0/24
	Endpoint = $UL0:$PORT0
	PersistentKeepalive = 5
	EOF
}

setup_kk() { # $1 = kernel BBR value
	teardown
	insmod "$KO" || return 1
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
	configs "$1"
	ip netns exec "$NS0" "$UWG" setconf uwg0 "$WORK/c0.conf" >/dev/null || return 1
	ip netns exec "$NS1" "$UWG" setconf uwg1 "$WORK/c1.conf" >/dev/null || return 1
	wait_link
}

setup_kr() { # kernel BBR=on in NS0, Rust BBR=off/FEC=off in NS1
	[ -n "$RUST" ] && [ -x "$RUST" ] || return 1
	teardown
	insmod "$KO" || return 1
	create_namespaces || return 1
	ip -n "$NS0" link add uwg0 type umbrawg || return 1
	mkdir -p /var/run/umbrawg
	ip netns exec "$NS1" env UMBRAWG_FEC=off UMBRAWG_BBR=off \
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
	configs on
	cat >"$WORK/c1-rust.conf" <<-EOF
	[Interface]
	PrivateKey = $K1
	ListenPort = $PORT1

	[Peer]
	PublicKey = $PUB0
	AllowedIPs = 10.95.0.0/24
	Endpoint = $UL0:$PORT0
	PersistentKeepalive = 5
	EOF
	ip netns exec "$NS0" "$UWG" setconf uwg0 "$WORK/c0.conf" >/dev/null || return 1
	"$UWG" setconf uwg1 "$WORK/c1-rust.conf" >/dev/null || return 1
	wait_link
}

stat_field() { # $1 = field in `uwg show uwg0 bbr-stats`
	ip netns exec "$NS0" "$UWG" show uwg0 bbr-stats 2>/dev/null |
		sed -n "s/^$1=//p" | head -1
}

run_tcp() { # $1 = label; sets TCP_MBIT, MAX_INFLIGHT, MAX_PACING
	local label=$1
	local srv="$WORK/iperf-$label.log"
	local pid i
	TCP_MBIT=0
	MAX_INFLIGHT=0
	MAX_PACING=0
	ip netns exec "$NS1" iperf3 -s -1 -p "$IPERF_PORT" -D --logfile "$srv" 2>/dev/null
	sleep 0.3
	ip netns exec "$NS0" iperf3 -c "$T1" -p "$IPERF_PORT" -t "$TCP_SECS" \
		>"$WORK/iperf-$label.txt" 2>&1 &
	pid=$!
	while kill -0 "$pid" 2>/dev/null; do
		local infl pace
		infl=$(stat_field inflight)
		pace=$(stat_field pacing_rate)
		[ -n "$infl" ] && [ "$infl" -gt "$MAX_INFLIGHT" ] && MAX_INFLIGHT=$infl
		[ -n "$pace" ] && [ "$pace" -gt "$MAX_PACING" ] && MAX_PACING=$pace
		sleep 0.4
	done
	wait "$pid"
	TCP_MBIT=$(grep -o '[0-9.]* [MG]bits/sec' "$WORK/iperf-$label.txt" | tail -1 |
		awk '{ if ($2 ~ /^G/) print $1 * 1000; else print $1 }')
	TCP_MBIT=${TCP_MBIT:-0}
	say "$label: TCP ${TCP_MBIT} Mbit/s, max inflight=$MAX_INFLIGHT, max pacing_rate=$MAX_PACING"
}

say "=== 1) kernel(BBR=on) <-> Rust(BBR=off, FEC=off), no ACK advertised"
if setup_kr; then
	run_tcp "mixed no-ack"
	[ "${TCP_MBIT%.*}" -gt 0 ] || fail "mixed no-ack: no TCP throughput"
	[ "$MAX_INFLIGHT" = 0 ] || fail "mixed no-ack: inflight grew to $MAX_INFLIGHT"
	[ "$MAX_PACING" = 0 ] || fail "mixed no-ack: pacer ran at $MAX_PACING"
	say "mixed bbr-stats: $(ip netns exec "$NS0" "$UWG" show uwg0 bbr-stats | tr '\n' ' ')"
else
	say "SKIP: kernel<->Rust (set RUST=/path/to/umbrawg to run it)"
fi
teardown

say "=== 2) kernel(BBR=on) <-> kernel(BBR=on), ACK peer"
setup_kk on || { say "setup failed"; exit 2; }
run_tcp "kk bbr-on"
[ "${TCP_MBIT%.*}" -gt 0 ] || fail "kk bbr-on: no TCP throughput"
[ "$MAX_INFLIGHT" -gt 0 ] || fail "kk bbr-on: no inflight tracked with ACK peer"
[ "$MAX_PACING" -gt 0 ] || fail "kk bbr-on: pacer inactive with ACK peer"
BBR_ON_MBIT=$TCP_MBIT
teardown

say "=== 3) kernel(BBR=off) <-> kernel(BBR=off), baseline"
setup_kk off || { say "setup failed"; exit 2; }
run_tcp "kk bbr-off"
BASELINE_MBIT=$TCP_MBIT
teardown

if [ "${BASELINE_MBIT%.*}" -gt 0 ]; then
	RATIO=$((BBR_ON_MBIT * 100 / BASELINE_MBIT))
	say "throughput ratio BBR on/off: ${RATIO}% (limit 70%)"
	[ "$RATIO" -ge 70 ] || fail "BBR=on throughput regressed to ${RATIO}% of baseline"
fi

if [ "$FAILED" = 0 ]; then
	say "PASS: BBR ACK gate"
	exit 0
fi
say "FAILED"
exit 1
