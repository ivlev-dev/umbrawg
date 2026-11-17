#!/bin/bash
set -euo pipefail
. "$(dirname "$0")/lib.sh"

for impl in umbrawg amneziawg; do
	for obf in 0 1; do
		for peers in 1 4; do
			printf '== %s obf=%s peers=%s: ' "$impl" "$obf" "$peers"
			if setup_topology "$impl" "$obf" "$peers" 2>"$TMP_DIR/setup.err"; then
				res=$(run_cell tcp 1420 1 0 "$peers" 2>>"$TMP_DIR/setup.err") || res="0,0,0"
				dev=$(iface_name 1 0)
				rx=$(cat "/sys/class/net/$NS1/statistics/rx_bytes" 2>/dev/null || echo 0)
				echo "OK bps/loss/ok=$res"
			else
				echo "FAIL"
				tail -5 "$TMP_DIR/setup.err" || true
			fi
			teardown
		done
	done
done
