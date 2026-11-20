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

NS0=uwgfec0
NS1=uwgfec1
VA=veth-fec0
VB=veth-fec1
T0=10.86.0.1
T1=10.86.0.2
UL0=172.30.86.1
UL1=172.30.86.2
PA=$((20000 + ($$ % 20000)))
PB=$((PA + 1))

MODULE_LOADED=0
FAILED=0
ACTIVE_NS=

mkdir -p "$WORK"
LOG=$WORK/test.log
: >"$LOG"

say() { printf '%s\n' "$*" | tee -a "$LOG"; }
note() { printf '%s\n' "$*" >>"$LOG"; }
fail() { say "FAIL: $*"; FAILED=1; }

cleanup() {
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
