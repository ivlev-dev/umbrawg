#!/bin/bash

BENCH_DIR="/root/umbrawg/bench"
TMP_DIR="$BENCH_DIR/tmp"
RES_DIR="$BENCH_DIR/results"

NS1="bwg1"
NS2="bwg2"
VETH1="vb1"
VETH2="vb2"
U1="10.200.0.1"
U2="10.200.0.2"
BASE_PORT=51820
IPERF_PORT=5201
UW_BIN="/root/umbrawg/tools/target/debug/uwg"
DUR=${DUR:-3}

mkdir -p "$TMP_DIR" "$RES_DIR"

impl_tool() {
	case "$1" in
		umbrawg) echo "$UW_BIN" ;;
		amneziawg) echo "awg" ;;
		*) echo "unknown impl: $1" >&2; return 1 ;;
	esac
}

impl_kind() {
	case "$1" in
		umbrawg|amneziawg) echo "$1" ;;
		*) echo "unknown impl: $1" >&2; return 1 ;;
	esac
}

obf_block() {
	local hp
	hp=$(new_key)
	cat <<'EOF' | sed "s|^HeaderProtectionKey[[:space:]]*=.*|HeaderProtectionKey = $hp|"
H1 = 712026294-712074283
H2 = 1504260570-1504277407
H3 = 2938347170-2938351405
H4 = 3916942126-3916960536
S1 = 34
S2 = 97
S3 = 31
S4 = 28
Jc = 6
Jmin = 292
Jmax = 1152
I1 = <b 0xc200000001087972af009f7ce47d04559703f31e174691922b896cb39e5ccdb74b8f6c46168d47652d74a98a2861c7349b5244b64eb876><rc 38><r 1000><r 161><t>
I2 = <b 0xe300000001127362d0c517f5aae98388afaf2809110ccc5610ed5923abbcbd29ac5c31816261d0e7ae44bb7fc33941><rc 40><r 1000><r 163><t>
I3 = <b 0xc30000000111bf75ad99b7b31b0d887c05054897ecd7d001911a53c4c9ab0067c318d6d5bf6519134da966559268219aca1fba4644b219ba2c84><rc 41><r 1000><r 153><t>
I4 = <b 0xe100000001093adb1b6b0cde0531700ea127f7f956bc499a0ab59bd6b0dc44c43085><rc 38><r 1000><r 176><t>
I5 = <b 0xe2000000010973760ff2b80f2c78420a91d8a812337b91c48c2844d7b63a2d><rc 40><r 1000><r 192><t>
HeaderProtectionKey = <HEADER_PROTECTION_KEY>
ContentPaddingAddition = 51-197
RekeyAfterTime = 104-149
RekeyTimeout = 5-8
RejectAfterTime = 184-199
KeepaliveTimeout = 9-12
MaxHandshakeAttempts = 18-23
RandomTrailers = on
DisableCookies = off
EOF
}

new_key() {
	"$UW_BIN" genkey
}

key_pub() {
	printf '%s\n' "$1" | "$UW_BIN" pubkey
}

teardown() {
	local pidf="$TMP_DIR/iperf3.pid"
	if [ -f "$pidf" ]; then
		kill "$(cat "$pidf")" 2>/dev/null || true
		rm -f "$pidf"
	fi
	for ns in "$NS1" "$NS2"; do
		ip netns del "$ns" 2>/dev/null || true
	done
	rm -f "$TMP_DIR"/iperf-*.json "$TMP_DIR"/iperf-*.err
}

iface_name() {
	case "$1" in
		1) echo "wg1_$2" ;;
		2) echo "wg2_$2" ;;
	esac
}

setup_topology() {
	local impl=$1 obf=$2 peers=$3
	local tool kind priv pub port i ns side dev
	tool=$(impl_tool "$impl")
	kind=$(impl_kind "$impl")

	teardown

	ip netns add "$NS1"
	ip netns add "$NS2"
	ip link add "$VETH1" netns "$NS1" type veth peer name "$VETH2" netns "$NS2"
	ip -n "$NS1" addr add "$U1/24" dev "$VETH1"
	ip -n "$NS2" addr add "$U2/24" dev "$VETH2"
	for ns in "$NS1" "$NS2"; do
		ip -n "$ns" link set lo up
	done
	ip -n "$NS1" link set "$VETH1" up
	ip -n "$NS2" link set "$VETH2" up

	: > "$TMP_DIR/keys"
	local k1 k2
	for ((i = 0; i < peers; i++)); do
		k1=$(new_key)
		k2=$(new_key)
		{
			printf 'peer%s_key1=%s\n' "$i" "$k1"
			printf 'peer%s_key2=%s\n' "$i" "$k2"
		} >> "$TMP_DIR/keys"
	done

	for ((i = 0; i < peers; i++)); do
		port=$((BASE_PORT + i))
		k1=$(grep "^peer${i}_key1=" "$TMP_DIR/keys" | cut -d= -f2-)
		k2=$(grep "^peer${i}_key2=" "$TMP_DIR/keys" | cut -d= -f2-)
		local pub1 pub2
		pub1=$(key_pub "$k1")
		pub2=$(key_pub "$k2")

		{
			printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n' "$k1" "$port"
			[ "$obf" = 1 ] && obf_block
			printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.9.%s.2/32\nEndpoint = %s:%s\nPersistentKeepalive = 1\n' \
				"$pub2" "$i" "$U2" "$port"
		} > "$TMP_DIR/${impl}-${i}-1.conf"
		{
			printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n' "$k2" "$port"
			[ "$obf" = 1 ] && obf_block
			printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.9.%s.1/32\nEndpoint = %s:%s\nPersistentKeepalive = 1\n' \
				"$pub1" "$i" "$U1" "$port"
		} > "$TMP_DIR/${impl}-${i}-2.conf"

		ip -n "$NS1" link add "$(iface_name 1 "$i")" type "$kind"
		ip -n "$NS2" link add "$(iface_name 2 "$i")" type "$kind"
		ip -n "$NS1" addr add "10.9.$i.1/24" dev "$(iface_name 1 "$i")"
		ip -n "$NS2" addr add "10.9.$i.2/24" dev "$(iface_name 2 "$i")"
		ip -n "$NS1" link set "$(iface_name 1 "$i")" up
		ip -n "$NS2" link set "$(iface_name 2 "$i")" up
		ip netns exec "$NS1" "$tool" setconf "$(iface_name 1 "$i")" "$TMP_DIR/${impl}-${i}-1.conf"
		ip netns exec "$NS2" "$tool" setconf "$(iface_name 2 "$i")" "$TMP_DIR/${impl}-${i}-2.conf"
	done

	ip netns exec "$NS2" iperf3 -s -D -p "$IPERF_PORT" --pidfile "$TMP_DIR/iperf3.pid" >/dev/null 2>&1

	for ((i = 0; i < peers; i++)); do
		local ok=0 try
		for try in 1 2 3 4 5; do
			if ip netns exec "$NS1" ping -c 1 -W 1 "10.9.$i.2" >/dev/null 2>&1; then
				ok=1
				break
			fi
			sleep 0.4
		done
		if [ "$ok" != 1 ]; then
			echo "handshake failed for peer $i ($impl obf=$obf)" >&2
			return 1
		fi
	done
}

set_cores() {
	local n=$1 cpu
	if [ "$n" -ge 6 ]; then
		for cpu in 1 2 3 4 5; do
			echo 1 > "/sys/devices/system/cpu/cpu$cpu/online" 2>/dev/null || true
		done
		sleep 0.5
		return 0
	fi
	for cpu in 1 2 3 4 5; do
		if [ "$cpu" -lt "$n" ]; then
			echo 1 > "/sys/devices/system/cpu/cpu$cpu/online" 2>/dev/null || true
		else
			echo 0 > "/sys/devices/system/cpu/cpu$cpu/online" 2>/dev/null || true
		fi
	done
	sleep 0.8
	local online
	online=$(nproc)
	if [ "$online" -ne "$n" ]; then
		echo "warn: requested $n cpus, have $online" >&2
		return 1
	fi
}

apply_loss() {
	local pct=$1 ns dev
	for ns in "$NS1" "$NS2"; do
		if [ "$ns" = "$NS1" ]; then dev=$VETH1; else dev=$VETH2; fi
		ip -n "$ns" qdisc del dev "$dev" root 2>/dev/null || true
		if [ "$pct" != 0 ]; then
			ip -n "$ns" qdisc replace dev "$dev" root netem loss "$pct%"
		fi
	done
}

run_cell() {
	local proto=$1 size=$2 conns=$3 loss=$4 peers=$5
	local i q r c dst f pids file_list
	apply_loss "$loss"
	pids=()
	file_list=""
	q=$((conns / peers))
	r=$((conns % peers))
	for ((i = 0; i < peers; i++)); do
		c=$((q + (i < r ? 1 : 0)))
		[ "$c" -gt 0 ] || continue
		dst="10.9.$i.2"
		f="$TMP_DIR/iperf-$i.json"
		rm -f "$f"
		if [ "$proto" = tcp ]; then
			ip netns exec "$NS1" iperf3 -c "$dst" -p "$IPERF_PORT" -t "$DUR" -P "$c" -J >"$f" 2>"$TMP_DIR/iperf-$i.err" &
		else
			ip netns exec "$NS1" iperf3 -c "$dst" -p "$IPERF_PORT" -u -b 0 -l "$size" -t "$DUR" -P "$c" -J >"$f" 2>"$TMP_DIR/iperf-$i.err" &
		fi
		pids+=($!)
		file_list="$file_list $f"
	done
	for i in "${pids[@]}"; do
		wait "$i" || true
	done
	python3 "$BENCH_DIR/parse_iperf.py" $file_list
}
