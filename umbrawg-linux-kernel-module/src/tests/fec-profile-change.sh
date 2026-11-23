#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Reproducer/regression test for runtime FEC profile changes.
#
# It builds a throw-away netns pair (two kernel umbrawg interfaces over a veth
# underlay) and walks a profile chain in both directions:
#
#   fresh setconf 2:1 -> set 3:2 -> set 8:2 -> set adaptive -> set off
#     -> set 2:1 -> setconf 8:2 -> setconf 8:2 (peer replacement)
#     -> one-sided 3:2 -> other side follows -> rapid flap
#
# For every step the script requires
#   * 0% ICMP loss in both directions,
#   * dropped_disabled did not grow (a stale/forgotten CAPS profile used to
#     turn the RX side into a black hole that dropped every shard),
#   * blocks_encoded/blocks_decoded moved on both sides while FEC is on,
#   * no new kernel WARN/BUG/oops.
#
# Needs root, umbrawg.ko and the `uwg` CLI. The module must not be loaded yet.
#
# Usage:
#   sudo KO=/path/to/umbrawg.ko UWG=/path/to/uwg src/tests/fec-profile-change.sh
#
# Exit code: 0 all steps passed, 1 a check failed, 2 setup/usage error.

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
KO=${KO:-$SCRIPT_DIR/../umbrawg.ko}
UWG=${UWG:-uwg}
WORK=${WORK:-/tmp/uwg-fec-profile-change.$$}
SETTLE_SECS=${SETTLE_SECS:-3}
PING_COUNT=${PING_COUNT:-10}

# Namespace and veth names are per-process: two copies of this test (for
# example from parallel CI jobs or a developer rerun) must not delete or
# collide with each other. uwg0 inside each namespace is still private.
NS0="uwgfec0-$$"
NS1="uwgfec1-$$"
VA="vfec0-$$"
VB="vfec1-$$"
T0=10.86.0.1
T1=10.86.0.2
UL0=172.30.86.1
UL1=172.30.86.2
PA=$((20000 + ($$ % 20000)))
PB=$((PA + 1))
IPERF_PORT=$((PA + 2))

MODULE_LOADED=0
FAILED=0
ACTIVE_NS=
SRV_PID=""

mkdir -p "$WORK"
LOG=$WORK/test.log
: >"$LOG"

say() { printf '%s\n' "$*" | tee -a "$LOG"; }
note() { printf '%s\n' "$*" >>"$LOG"; }
fail() { say "FAIL: $*"; FAILED=1; }

cleanup() {
	if [ -n "$SRV_PID" ]; then
		kill "$SRV_PID" 2>/dev/null
	fi
	for ns in $ACTIVE_NS "$NS0" "$NS1"; do
		ip netns del "$ns" 2>/dev/null
	done
	if [ "$MODULE_LOADED" = 1 ]; then
		rmmod umbrawg 2>/dev/null
	fi
}
trap cleanup EXIT INT TERM

need() {
	command -v "$1" >/dev/null 2>&1 || { say "missing required tool: $1"; exit 2; }
}

[ "$(id -u)" = 0 ] || { say "must run as root"; exit 2; }
need ip
need ping
need insmod
[ -f "$KO" ] || { say "kernel module not found: $KO (run make first or set KO=)"; exit 2; }
command -v "$UWG" >/dev/null 2>&1 || { say "uwg CLI not found: $UWG (set UWG=)"; exit 2; }
if lsmod 2>/dev/null | grep -q '^umbrawg '; then
	say "umbrawg is already loaded; unload it first (rmmod umbrawg)"
	exit 2
fi
if ip netns list 2>/dev/null | grep -qE "^($NS0|$NS1)\b"; then
	say "stale netns $NS0/$NS1 present; remove them first"
	exit 2
fi

start_ts=$(date +%s)
say "insmod $KO"
insmod "$KO" || { say "insmod failed"; exit 2; }
MODULE_LOADED=1
ACTIVE_NS="$NS0 $NS1"

ip netns add "$NS0" || exit 2
ip netns add "$NS1" || exit 2
ip link add "$VA" type veth peer name "$VB" || exit 2
ip link set "$VA" netns "$NS0"
ip link set "$VB" netns "$NS1"
ip -n "$NS0" addr add "$UL0/24" dev "$VA"
ip -n "$NS1" addr add "$UL1/24" dev "$VB"
ip -n "$NS0" link set "$VA" up
ip -n "$NS1" link set "$VB" up
ip -n "$NS0" link add uwg0 type umbrawg || exit 2
ip -n "$NS1" link add uwg0 type umbrawg || exit 2
ip -n "$NS0" addr add "$T0/24" dev uwg0
ip -n "$NS1" addr add "$T1/24" dev uwg0
ip -n "$NS0" link set uwg0 mtu 1420 up
ip -n "$NS1" link set uwg0 mtu 1420 up

K0=$("$UWG" genkey) || exit 2
K1=$("$UWG" genkey) || exit 2
P0=$(printf '%s' "$K0" | "$UWG" pubkey) || exit 2
P1=$(printf '%s' "$K1" | "$UWG" pubkey) || exit 2

write_conf() { # file priv port peer endpoint_ip endpoint_port fec
	cat >"$1" <<EOF
[Interface]
PrivateKey = $2
ListenPort = $3
FEC = $7

[Peer]
PublicKey = $4
AllowedIPs = 10.86.0.0/24
Endpoint = $5:$6
PersistentKeepalive = 5
EOF
}

setconf_both() { # profile
	write_conf "$WORK/c0" "$K0" "$PA" "$P1" "$UL1" "$PB" "$1"
	write_conf "$WORK/c1" "$K1" "$PB" "$P0" "$UL0" "$PA" "$1"
	note "+ setconf FEC=$1 (both, peer replacement)"
	ip netns exec "$NS0" "$UWG" setconf uwg0 "$WORK/c0" >>"$LOG" 2>&1 || fail "setconf ns0 $1"
	ip netns exec "$NS1" "$UWG" setconf uwg0 "$WORK/c1" >>"$LOG" 2>&1 || fail "setconf ns1 $1"
}

set_fec() { # ns profile
	note "+ set fec $2 on $1"
	ip netns exec "$1" "$UWG" set uwg0 fec "$2" >>"$LOG" 2>&1 ||
		fail "set fec $2 on $1"
}

stat() { # ns key
	ip netns exec "$1" "$UWG" show uwg0 fec-stats 2>/dev/null |
		sed -n "s/^$2=//p" | head -1
}

profile() { # ns
	ip netns exec "$1" "$UWG" show uwg0 fec 2>/dev/null | head -1
}

# Wait until both directions carry ICMP again.
wait_link() {
	local i
	for i in $(seq 1 $((SETTLE_SECS * 4))); do
		if ip netns exec "$NS0" ping -c 1 -W 1 "$T1" >/dev/null 2>&1 &&
		   ip netns exec "$NS1" ping -c 1 -W 1 "$T0" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.25
	done
	return 1
}

ping_loss() { # ns target
	local out loss
	out=$(ip netns exec "$1" ping -c "$PING_COUNT" -i 0.1 -W 1 "$2" 2>&1)
	loss=$(printf '%s\n' "$out" | sed -n 's/.* \([0-9]*\)% packet loss.*/\1/p' | head -1)
	printf '%s' "${loss:-100}"
}

veth_tx_packets() { # ns dev
	ip netns exec "$1" cat /proc/net/dev 2>/dev/null |
		awk -v dev="$2:" '$1 == dev { print $11 }'
}

set_keepalive() { # ns peer_pubkey seconds
	local out
	out=$(ip netns exec "$1" "$UWG" set uwg0 peer "$2" \
		persistent-keepalive "$3" 2>&1) ||
		fail "set persistent-keepalive $3 on $1: $out"
}

iperf_tcp() { # seconds tag
	ip netns exec "$NS1" iperf3 -s -1 -p "$IPERF_PORT" -D \
		--pidfile "$WORK/srv.pid" --logfile "$WORK/srv.log" \
		>/dev/null 2>&1
	sleep 0.3
	SRV_PID=$(cat "$WORK/srv.pid" 2>/dev/null || true)
	ip netns exec "$NS0" iperf3 -c "$T1" -p "$IPERF_PORT" -t "$1" -P 1 -J \
		>"$WORK/$2.json" 2>"$WORK/$2.err"
	local rc=$?
	if [ -n "$SRV_PID" ]; then
		kill "$SRV_PID" 2>/dev/null
		SRV_PID=""
	fi
	[ "$rc" -eq 0 ] || { printf 'FAIL'; return; }
	python3 -c 'import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print(round(d["end"]["sum_received"]["bits_per_second"]/1e6,1))
except Exception:
    print("FAIL")' "$WORK/$2.json"
}

probe_encoded() { # label: packets encoded by NS1 during a small reverse burst
	local label=$1 pre post d
	pre=$(stat "$NS1" blocks_encoded)
	pre=${pre:-0}
	ip netns exec "$NS1" ping -f -c 200 -W 1 "$T0" >/dev/null 2>&1 || true
	sleep 0.3
	post=$(stat "$NS1" blocks_encoded)
	post=${post:-0}
	d=$((post - pre))
	[ "$d" -ge 0 ] || d=0
	note "  $label: $NS1 blocks_encoded +$d"
	printf '%s' "$d"
}

declare -A BASE_D BASE_E BASE_C

# Apply a profile, then require: 0% ping loss both ways, no growth of
# dropped_disabled on either side, and (while FEC is on) both directions
# actually encode and decode blocks. Baselines are taken right after the
# change so a setconf peer replacement (which resets the counters) is fine.
run_step() { # name profile apply_function fec_on
	local name=$1 prof=$2 apply=$3 fec_on=$4 i ns loss d e c
	say "=== $name (profile $prof)"
	"$apply" "$prof"
	sleep 0.3
	for i in 0 1; do
		if [ "$i" = 0 ]; then ns=$NS0; else ns=$NS1; fi
		BASE_D[$ns]=$(stat "$ns" dropped_disabled)
		BASE_E[$ns]=$(stat "$ns" blocks_encoded)
		BASE_C[$ns]=$(stat "$ns" blocks_decoded)
	done
	wait_link || { fail "$name: tunnel did not come back"; return; }
	loss=$(ping_loss "$NS0" "$T1")
	[ "$loss" = 0 ] || fail "$name: forward ping loss=${loss}%"
	loss=$(ping_loss "$NS1" "$T0")
	[ "$loss" = 0 ] || fail "$name: reverse ping loss=${loss}%"
	for i in 0 1; do
		if [ "$i" = 0 ]; then ns=$NS0; else ns=$NS1; fi
		d=$(stat "$ns" dropped_disabled)
		e=$(stat "$ns" blocks_encoded)
		c=$(stat "$ns" blocks_decoded)
		note "  $ns profile=$(profile "$ns") dropped_disabled=$d blocks_encoded=$e blocks_decoded=$c"
		[ "${d:-0}" -le "${BASE_D[$ns]:-0}" ] ||
			fail "$name: $ns dropped_disabled grew ${BASE_D[$ns]} -> $d"
		if [ "$fec_on" = 1 ]; then
			[ "${e:-0}" -gt "${BASE_E[$ns]:-0}" ] ||
				fail "$name: $ns blocks_encoded did not advance"
			[ "${c:-0}" -gt "${BASE_C[$ns]:-0}" ] ||
				fail "$name: $ns blocks_decoded did not advance"
		fi
	done
}

apply_both() { setconf_both "$1"; }
apply_set_both() { set_fec "$NS0" "$1"; sleep 0.2; set_fec "$NS1" "$1"; }
apply_set_reverse() { set_fec "$NS1" "$1"; sleep 0.2; set_fec "$NS0" "$1"; }

run_step "fresh setconf 2:1" 2:1 apply_both 1
run_step "set 2:1 -> 3:2" 3:2 apply_set_both 1
run_step "set 3:2 -> 8:2" 8:2 apply_set_reverse 1
run_step "setconf 8:2 (peer replacement, same profile)" 8:2 apply_both 1
run_step "setconf 8:2 -> 2:1" 2:1 apply_both 1

# Adaptive starts in legacy mode on a clean link (it arms only after >1% loss
# and a full window), so only the black-hole and loss checks apply here.
run_step "set 2:1 -> adaptive" adaptive apply_set_both 0
run_step "set adaptive -> off" off apply_set_both 0
run_step "setconf off -> 2:1" 2:1 apply_both 1

check_link() { # label
	local label=$1 loss
	if ! wait_link; then
		say "--- $label diagnostics:"
		for ns in "$NS0" "$NS1"; do
			note "  $ns profile=$(profile "$ns")"
			ip netns exec "$ns" "$UWG" show uwg0 fec-stats >>"$LOG" 2>&1
			ip netns exec "$ns" "$UWG" show uwg0 latest-handshakes >>"$LOG" 2>&1
		done
		fail "$label: tunnel did not come back"
		return 1
	fi
	loss=$(ping_loss "$NS0" "$T1")
	[ "$loss" = 0 ] || fail "$label: forward ping loss=${loss}%"
	loss=$(ping_loss "$NS1" "$T0")
	[ "$loss" = 0 ] || fail "$label: reverse ping loss=${loss}%"
}

# One side turns FEC off while the other keeps running it. The still-enabled
# side must be told to stop sending shards: a fully-off device has to retract
# its old advertisement even though it no longer advertises anything.
say "=== one-sided off on $NS0 while $NS1 stays 2:1"
set_fec "$NS0" off
sleep 2.5
check_link "one-sided off"
say "=== $NS0 back to 2:1"
set_fec "$NS0" 2:1
sleep 1
check_link "one-sided off recovery"

# Operator applies one side first: the tunnel must stay usable (legacy
# fallback) and must converge once the other side follows.
say "=== one-sided change 2:1 -> 3:2 on $NS0 only"
set_fec "$NS0" 3:2
sleep 0.5
check_link "one-sided profile change"
say "=== other side follows to 3:2"
set_fec "$NS1" 3:2
sleep 0.5
check_link "one-sided profile sync"

# Rapid flap under traffic: the profile must not leave the tunnel dead.
say "=== rapid flap 3:2 <-> 8:2 under ping"
( while :; do ip netns exec "$NS0" ping -c 1 -W 1 "$T1" >/dev/null 2>&1; done ) &
PING_LOOP=$!
for prof in 8:2 3:2 8:2 3:2; do
	set_fec "$NS0" "$prof"
	sleep 0.2
	set_fec "$NS1" "$prof"
	sleep 0.4
done
kill "$PING_LOOP" 2>/dev/null
wait "$PING_LOOP" 2>/dev/null
wait_link || fail "flap: tunnel did not come back"
loss=$(ping_loss "$NS0" "$T1")
[ "$loss" = 0 ] || fail "flap: forward ping loss=${loss}%"
loss=$(ping_loss "$NS1" "$T0")
[ "$loss" = 0 ] || fail "flap: reverse ping loss=${loss}%"

# The first CAPS after a profile change can be lost. Both sides must still
# converge (the fast retry, the bounded identical-repeat answer and the
# deferred 200 ms answer exist for exactly this). Ping alone would pass on the
# legacy fallback with a stale CAPS, so the counters have to prove that FEC is
# really agreed again: blocks_encoded only advances when the peer's CAPS
# advertises the local profile, and blocks_decoded only when the peer's shards
# match. The deferred changed-CAPS branch itself is covered deterministically
# by the load-time self-test (EXT CAPS self-test, run by insmod).
say "=== profile change while the first CAPS is lost"
if command -v tc >/dev/null 2>&1; then
	ip netns exec "$NS0" tc qdisc replace dev "$VA" root netem \
		limit 200000 loss 100%
	ip netns exec "$NS1" tc qdisc replace dev "$VB" root netem \
		limit 200000 loss 100%
	set_fec "$NS0" 8:2
	set_fec "$NS1" 8:2
	sleep 0.4
	ip netns exec "$NS0" tc qdisc del dev "$VA" root 2>/dev/null
	ip netns exec "$NS1" tc qdisc del dev "$VB" root 2>/dev/null
	check_link "CAPS loss recovery"
	[ "$(profile "$NS0")" = "8:2" ] ||
		fail "CAPS loss: $NS0 profile is $(profile "$NS0")"
	[ "$(profile "$NS1")" = "8:2" ] ||
		fail "CAPS loss: $NS1 profile is $(profile "$NS1")"
	# The bounded retry and the deferred answer converge within ~1 s.
	sleep 2
	b0e=$(stat "$NS0" blocks_encoded); b0e=${b0e:-0}
	b0c=$(stat "$NS0" blocks_decoded); b0c=${b0c:-0}
	b1e=$(stat "$NS1" blocks_encoded); b1e=${b1e:-0}
	b1c=$(stat "$NS1" blocks_decoded); b1c=${b1c:-0}
	dd0=$(stat "$NS0" dropped_disabled); dd0=${dd0:-0}
	dd1=$(stat "$NS1" dropped_disabled); dd1=${dd1:-0}
	ip netns exec "$NS0" ping -f -c 200 -W 1 "$T1" >/dev/null 2>&1 || true
	ip netns exec "$NS1" ping -f -c 200 -W 1 "$T0" >/dev/null 2>&1 || true
	sleep 0.3
	a0e=$(stat "$NS0" blocks_encoded); a0e=${a0e:-0}
	a0c=$(stat "$NS0" blocks_decoded); a0c=${a0c:-0}
	a1e=$(stat "$NS1" blocks_encoded); a1e=${a1e:-0}
	a1c=$(stat "$NS1" blocks_decoded); a1c=${a1c:-0}
	dd0e=$(stat "$NS0" dropped_disabled); dd0e=${dd0e:-0}
	dd1e=$(stat "$NS1" dropped_disabled); dd1e=${dd1e:-0}
	note "  CAPS loss: $NS0 enc +$((a0e - b0e)) dec +$((a0c - b0c)), $NS1 enc +$((a1e - b1e)) dec +$((a1c - b1c))"
	[ "$a0e" -gt "$b0e" ] ||
		fail "CAPS loss: $NS0 blocks_encoded did not advance (legacy after lost CAPS)"
	[ "$a0c" -gt "$b0c" ] ||
		fail "CAPS loss: $NS0 blocks_decoded did not advance"
	[ "$a1e" -gt "$b1e" ] ||
		fail "CAPS loss: $NS1 blocks_encoded did not advance (legacy after lost CAPS)"
	[ "$a1c" -gt "$b1c" ] ||
		fail "CAPS loss: $NS1 blocks_decoded did not advance"
	[ "$dd0e" -le "$dd0" ] ||
		fail "CAPS loss: $NS0 dropped_disabled grew $dd0 -> $dd0e"
	[ "$dd1e" -le "$dd1" ] ||
		fail "CAPS loss: $NS1 dropped_disabled grew $dd1 -> $dd1e"
else
	note "tc missing: lost-CAPS convergence check skipped"
fi

# Regression: two devices with FEC off must stay silent. A zero
# CAPS retracts a stale advertisement, but it is itself an extension frame;
# treating it as proof that the peer still sends extension traffic made both
# kernels answer each other with another zero CAPS every 2 s forever.
# Keepalives are disabled for the measurement so the packet count reflects
# only extension control traffic (the tunnel is idle otherwise).
say "=== all-off silence on both sides (10 s)"
set_fec "$NS0" off
set_fec "$NS1" off
set_keepalive "$NS0" "$P1" 0
set_keepalive "$NS1" "$P0" 0
sleep 3
before0=$(veth_tx_packets "$NS0" "$VA")
before1=$(veth_tx_packets "$NS1" "$VB")
sleep 10
after0=$(veth_tx_packets "$NS0" "$VA")
after1=$(veth_tx_packets "$NS1" "$VB")
if [ -z "$before0" ] || [ -z "$after0" ] ||
   [ -z "$before1" ] || [ -z "$after1" ]; then
	fail "all-off: could not read underlay packet counters"
else
	d0=$((after0 - before0))
	d1=$((after1 - before1))
	note "  all-off 10s underlay tx packets: $NS0=$d0 $NS1=$d1"
	# An occasional leftover frame is fine; the former ping-pong produced a
	# zero CAPS every 2 s (about five per side in this window).
	[ "$d0" -le 2 ] ||
		fail "all-off: $NS0 sent $d0 control packets in 10 s"
	[ "$d1" -le 2 ] ||
		fail "all-off: $NS1 sent $d1 control packets in 10 s"
fi
say "=== all-off -> 2:1 recovery"
set_fec "$NS0" 2:1
set_fec "$NS1" 2:1
sleep 1
check_link "all-off recovery"

# Adaptive must ignore pure reordering and still arm on real loss. Reordering
# is simulated by delaying a quarter of the underlay packets. netem's own
# delay/reorder already costs some TCP throughput, so the throughput check is
# only a coarse guard against the ~50 % FEC overhead a wrong decision would
# add; the authoritative check is that adaptive stays off and blocks_encoded
# does not grow. The kernel self-test covers the decision deterministically at
# module load.
if command -v iperf3 >/dev/null 2>&1 && command -v tc >/dev/null 2>&1 &&
   command -v python3 >/dev/null 2>&1; then
	say "=== adaptive vs reorder 25% / loss 2%"
	set_fec "$NS0" adaptive
	sleep 0.2
	set_fec "$NS1" adaptive
	sleep 0.5
	check_link "adaptive reorder baseline"
	BASE=$(iperf_tcp 4 adbase)
	ip netns exec "$NS0" tc qdisc add dev "$VA" root netem limit 200000 \
		delay 200us reorder 25% 50% ||
		fail "adaptive: could not install reorder netem"
	REORDER=$(iperf_tcp 4 adreorder)
	ip netns exec "$NS0" tc qdisc del dev "$VA" root 2>/dev/null
	sleep 0.3
	R_ENC=$(probe_encoded reorder)
	note "  adaptive reorder TCP: base=$BASE reorder=$REORDER Mbit/s"
	if [ "$BASE" != FAIL ] && [ "$REORDER" != FAIL ]; then
		python3 - "$BASE" "$REORDER" <<-'PY'
		import sys
		base = float(sys.argv[1])
		reorder = float(sys.argv[2])
		drop = (base - reorder) * 100.0 / base
		print(f"  adaptive reorder TCP drop: {drop:.1f}% (limit 20%)")
		sys.exit(0 if drop < 20.0 else 1)
		PY
		[ $? -eq 0 ] || fail "adaptive: TCP degraded more than 20% under reorder"
	else
		fail "adaptive: iperf3 did not complete under reorder"
	fi
	# A false positive shows up immediately: adaptive TX would encode the
	# small reverse burst even though the reordered link lost nothing.
	[ "${R_ENC:-0}" -le 2 ] ||
		fail "adaptive armed on reordering (blocks_encoded +$R_ENC)"

	ip netns exec "$NS0" tc qdisc add dev "$VA" root netem limit 200000 \
		loss 2% || fail "adaptive: could not install loss netem"
	iperf_tcp 5 adloss >/dev/null
	ip netns exec "$NS0" tc qdisc del dev "$VA" root 2>/dev/null
	sleep 0.3
	L_ENC=$(probe_encoded loss)
	[ "${L_ENC:-0}" -ge 10 ] ||
		fail "adaptive did not arm on 2% loss (blocks_encoded +$L_ENC)"
else
	note "iperf3/tc/python3 missing: adaptive reorder check skipped"
fi

# Kernel log: only lines emitted after the test started matter.
if dmesg --since "@$start_ts" >"$WORK/dmesg" 2>/dev/null; then
	if grep -Eq "WARNING:|BUG:|Oops|Call Trace" "$WORK/dmesg"; then
		say "--- new kernel splat:"
		grep -E -A 5 "WARNING:|BUG:|Oops|Call Trace" "$WORK/dmesg" | tee -a "$LOG"
		fail "kernel WARN/BUG/oops during the test"
	fi
else
	note "dmesg --since is not supported, kernel log not checked"
fi

if [ "$FAILED" = 0 ]; then
	say "PASS: FEC profile changes keep 0% loss and no disabled shard drops"
	exit 0
fi
say "FAILED"
exit 1
