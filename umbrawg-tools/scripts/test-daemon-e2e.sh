#!/usr/bin/env bash
set -euo pipefail

umask 077

PROGRAM="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_ROOT="$(cd -- "$TOOLS_DIR/.." && pwd)"

IFACE="${IFACE:-uwge2e}"
KEEP_ARTIFACTS="${KEEP_ARTIFACTS:-0}"

skip() {
    printf 'SKIP: %s\n' "$*" >&2
    exit 0
}

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

first_existing_file() {
    local candidate
    for candidate in "$@"; do
        if [ -n "$candidate" ] && [ -x "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

resolve_uwg() {
    local found
    if [ -n "${UWG:-}" ]; then
        printf '%s\n' "$UWG"
        return 0
    fi
    if found="$(first_existing_file "$TOOLS_DIR/target/release/uwg" "$TOOLS_DIR/target/debug/uwg")"; then
        printf '%s\n' "$found"
        return 0
    fi
    command -v uwg
}

resolve_daemon() {
    local found
    if [ -n "${DAEMON:-}" ]; then
        printf '%s\n' "$DAEMON"
        return 0
    fi
    if found="$(first_existing_file \
        "$WORKSPACE_ROOT/rust/target/release/umbrawg" \
        "$WORKSPACE_ROOT/umbrawg-rs/target/release/umbrawg" \
        "$WORKSPACE_ROOT/rust-parallel-rx/target/release/umbrawg")"; then
        printf '%s\n' "$found"
        return 0
    fi
    return 1
}

can_manage_network() {
    ip link set lo up >/dev/null 2>&1
}

ensure_network_namespace() {
    if [ "${UMBRAWG_E2E_NAMESPACE:-0}" = "1" ]; then
        return 0
    fi
    if can_manage_network; then
        return 0
    fi
    command -v unshare >/dev/null 2>&1 \
        || skip "нет CAP_NET_ADMIN, а unshare недоступен"
    unshare -Urn true >/dev/null 2>&1 \
        || skip "нет CAP_NET_ADMIN и unshare -Urn не работает"
    exec unshare -Urn env UMBRAWG_E2E_NAMESPACE=1 "$0" "$@"
}

probe_tun() {
    local name="uwgprobe$$"
    [ -c /dev/net/tun ] || return 1
    ip tuntap add dev "$name" mode tun >/dev/null 2>&1 || return 1
    ip link del "$name" >/dev/null 2>&1 || true
    return 0
}

UWG_BIN="$(resolve_uwg)" || skip "uwg не найден (задайте UWG)"
DAEMON_BIN="$(resolve_daemon)" || skip "демон umbrawg не найден (задайте DAEMON)"
[ -x "$UWG_BIN" ] || skip "uwg не исполняемый: $UWG_BIN"
[ -x "$DAEMON_BIN" ] || skip "демон не исполняемый: $DAEMON_BIN"
command -v ip >/dev/null 2>&1 || skip "нет ip (iproute2)"

ensure_network_namespace
ip link set lo up >/dev/null 2>&1 || fail "не удалось поднять loopback"
probe_tun || skip "TUN недоступен (нет /dev/net/tun или CAP_NET_ADMIN)"

RUNDIR="$(mktemp -d "${TMPDIR:-/tmp}/umbrawg-e2e.XXXXXX")"
SOCK="$RUNDIR/$IFACE.sock"
DAEMON_PID=""

cleanup() {
    local status=$?
    set +e
    if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
    fi
    if [ "$KEEP_ARTIFACTS" = "1" ]; then
        printf 'артефакты прогона: %s\n' "$RUNDIR" >&2
    else
        rm -rf "$RUNDIR"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

uwg_ok() {
    local label="$1"
    local outfile="$2"
    shift 2
    local errfile="$RUNDIR/stderr-$label"
    local status=0
    UWG_RUNTIME_DIR="$RUNDIR" NO_COLOR=1 "$UWG_BIN" "$@" >"$outfile" 2>"$errfile" || status=$?
    if [ "$status" -ne 0 ]; then
        printf -- '--- stderr (%s) ---\n' "$label" >&2
        cat "$errfile" >&2
        fail "$label: uwg завершился с кодом $status"
    fi
    if [ -s "$errfile" ]; then
        printf -- '--- stderr (%s) ---\n' "$label" >&2
        cat "$errfile" >&2
        fail "$label: неожиданный вывод в stderr"
    fi
    rm -f "$errfile"
}

uwg_fails() {
    local label="$1"
    local expected="$2"
    shift 2
    local errfile="$RUNDIR/stderr-$label"
    local status=0
    UWG_RUNTIME_DIR="$RUNDIR" NO_COLOR=1 "$UWG_BIN" "$@" >"$RUNDIR/stdout-$label" 2>"$errfile" || status=$?
    if [ "$status" -eq 0 ]; then
        fail "$label: ожидался ненулевой код возврата"
    fi
    if [ ! -s "$errfile" ]; then
        fail "$label: ожидалось сообщение об ошибке в stderr"
    fi
    if [ -n "$expected" ] && ! grep -Fq -- "$expected" "$errfile"; then
        printf -- '--- stderr (%s) ---\n' "$label" >&2
        cat "$errfile" >&2
        fail "$label: в stderr нет строки «$expected»"
    fi
}

expect_contains() {
    local file="$1"
    local needle="$2"
    local label="$3"
    if ! grep -Fq -- "$needle" "$file"; then
        printf -- '--- %s ---\n' "$file" >&2
        cat "$file" >&2
        fail "$label: не найдено «$needle»"
    fi
}

canonicalize() {
    awk '
    function trim(text) {
        gsub(/^[ \t\r]+/, "", text)
        gsub(/[ \t\r]+$/, "", text)
        return text
    }
    function normalize(key, value,    parts, count, i, j, tmp, out) {
        if (value == "YES") value = "yes"
        if (value == "NO") value = "no"
        if (key == "allowedips") {
            count = split(value, parts, ",")
            for (i = 1; i <= count; i++) parts[i] = trim(parts[i])
            for (i = 2; i <= count; i++) {
                tmp = parts[i]
                j = i - 1
                while (j >= 1 && parts[j] > tmp) {
                    parts[j + 1] = parts[j]
                    j--
                }
                parts[j + 1] = tmp
            }
            out = parts[1]
            for (i = 2; i <= count; i++) out = out ", " parts[i]
            return out
        }
        return value
    }
    function flush(    key, pk) {
        if (!have) return
        if (kind == 1) {
            for (key in entry) print "I|" key "=" entry[key]
        } else {
            pk = entry["publickey"]
            for (key in entry) {
                if (key != "publickey") print "P|" pk "|" key "=" entry[key]
            }
            print "P|" pk "|publickey=" pk
        }
        delete entry
        have = 0
    }
    {
        line = trim($0)
        if (line == "" || line ~ /^[#;]/) next
        if (line ~ /^\[.*\]$/) {
            flush()
            kind = (tolower(line) == "[peer]") ? 2 : 1
            have = 1
            next
        }
        if (!have) next
        pos = index(line, "=")
        if (pos == 0) next
        key = tolower(trim(substr(line, 1, pos - 1)))
        value = trim(substr(line, pos + 1))
        entry[key] = normalize(key, value)
    }
    END { flush() }
    ' "$1" | LC_ALL=C sort
}

compare_configs() {
    local expected="$1"
    local actual="$2"
    local label="$3"
    canonicalize "$expected" >"$RUNDIR/canon-expected.txt"
    canonicalize "$actual" >"$RUNDIR/canon-actual.txt"
    if ! diff -u "$RUNDIR/canon-expected.txt" "$RUNDIR/canon-actual.txt"; then
        fail "$label: showconf не совпадает с исходным конфигом"
    fi
}

wait_for_socket() {
    local deadline=$((SECONDS + 15))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if [ -S "$SOCK" ]; then
            kill -0 "$DAEMON_PID" 2>/dev/null && return 0
            return 1
        fi
        kill -0 "$DAEMON_PID" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

wait_until() {
    local timeout="$1"
    shift
    local deadline=$((SECONDS + timeout))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if "$@"; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

socket_absent() {
    [ ! -e "$SOCK" ]
}

start_daemon() {
    printf '== запуск демона: %s %s (UWG_RUNTIME_DIR=%s) ==\n' "$DAEMON_BIN" "$IFACE" "$RUNDIR"
    : >"$RUNDIR/daemon.log"
    UWG_RUNTIME_DIR="$RUNDIR" \
        UMBRAWG_RUNTIME_DIR="$RUNDIR" \
        UMBRAWG_LOG_LEVEL="${UMBRAWG_LOG_LEVEL:-info}" \
        "$DAEMON_BIN" --foreground "$IFACE" >>"$RUNDIR/daemon.log" 2>&1 &
    DAEMON_PID=$!
    if ! wait_for_socket; then
        printf -- '--- daemon.log ---\n' >&2
        cat "$RUNDIR/daemon.log" >&2 || true
        fail "демон не создал сокет $SOCK"
    fi
    printf 'сокет готов: %s\n' "$SOCK"
}

stop_daemon() {
    if [ -z "${DAEMON_PID:-}" ]; then
        return 0
    fi
    if kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        local deadline=$((SECONDS + 10))
        while kill -0 "$DAEMON_PID" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do
            sleep 0.1
        done
        if kill -0 "$DAEMON_PID" 2>/dev/null; then
            kill -KILL "$DAEMON_PID" 2>/dev/null || true
        fi
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    DAEMON_PID=""
}

gen_key() {
    local label="$1"
    local errfile="$RUNDIR/stderr-$label"
    local status=0
    local value
    value="$(UWG_RUNTIME_DIR="$RUNDIR" "$UWG_BIN" genkey 2>"$errfile")" || status=$?
    if [ "$status" -ne 0 ]; then
        cat "$errfile" >&2
        fail "$label: genkey завершился с кодом $status"
    fi
    if [ -s "$errfile" ]; then
        cat "$errfile" >&2
        fail "$label: неожиданный вывод genkey в stderr"
    fi
    printf '%s\n' "$value"
}

derive_pub() {
    local label="$1"
    local private="$2"
    local errfile="$RUNDIR/stderr-$label"
    local status=0
    local value
    value="$(printf '%s\n' "$private" | UWG_RUNTIME_DIR="$RUNDIR" "$UWG_BIN" pubkey 2>"$errfile")" || status=$?
    if [ "$status" -ne 0 ]; then
        cat "$errfile" >&2
        fail "$label: pubkey завершился с кодом $status"
    fi
    if [ -s "$errfile" ]; then
        cat "$errfile" >&2
        fail "$label: неожиданный вывод pubkey в stderr"
    fi
    printf '%s\n' "$value"
}

printf 'uwg: %s\n' "$UWG_BIN"
printf 'демон: %s\n' "$DAEMON_BIN"
printf 'интерфейс: %s\n' "$IFACE"

uwg_ok version "$RUNDIR/version.txt" version
expect_contains "$RUNDIR/version.txt" "uwg v" "version"
uwg_ok help "$RUNDIR/help.txt" help
expect_contains "$RUNDIR/help.txt" "Usage: uwg" "help"
printf 'version/help: OK\n'

PRIVATE="$(gen_key genkey-main)"
PEER1_PRIVATE="$(gen_key genkey-peer1)"
PEER2_PRIVATE="$(gen_key genkey-peer2)"
PEER3_PRIVATE="$(gen_key genkey-peer3)"
PEER1_PUB="$(derive_pub pubkey-peer1 "$PEER1_PRIVATE")"
PEER2_PUB="$(derive_pub pubkey-peer2 "$PEER2_PRIVATE")"
PEER3_PUB="$(derive_pub pubkey-peer3 "$PEER3_PRIVATE")"
PSK="$(gen_key genpsk-main)"
HEADER_KEY="$(gen_key genkey-header)"

cat >"$RUNDIR/full.conf" <<EOF
[Interface]
PrivateKey = $PRIVATE
ListenPort = 51821
FwMark = 0x1234
Jc = 4
Jmin = 50
Jmax = 1000
S1 = 15
S2 = 30
S3 = 45
S4 = 60
H1 = 1000-1010
H2 = 2000-2010
H3 = 3000-3010
H4 = 4000-4010
I1 = <b 0x160d2f><c>
I2 = <r 32>
I3 = <t>
I4 = <rc 16>
I5 = <rd 8>
HeaderProtectionKey = $HEADER_KEY
ContentPaddingAddition = 10-20
RekeyAfterTime = 100-120
RekeyTimeout = 5
RejectAfterTime = 180
KeepaliveTimeout = 10
MaxHandshakeAttempts = 18
RandomTrailers = on
DisableCookies = off

[Peer]
PublicKey = $PEER1_PUB
PresharedKey = $PSK
AllowedIPs = 10.99.0.0/24, fd00::/64
Endpoint = 192.0.2.10:51820
PersistentKeepalive = 25
AdvancedSecurity = on

[Peer]
PublicKey = $PEER2_PUB
AllowedIPs = 10.99.1.0/24
AdvancedSecurity = off
EOF

start_daemon

printf '== setconf: полный конфиг 3.1 ==\n'
uwg_ok setconf "$RUNDIR/setconf.out" setconf "$IFACE" "$RUNDIR/full.conf"
uwg_ok showconf-1 "$RUNDIR/showconf-1.txt" showconf "$IFACE"
compare_configs "$RUNDIR/full.conf" "$RUNDIR/showconf-1.txt" "setconf/showconf"
printf 'setconf/showconf: OK\n'

printf '== show: параметры устройства и пиров ==\n'
uwg_ok show-pretty "$RUNDIR/show-pretty.txt" show "$IFACE"
expect_contains "$RUNDIR/show-pretty.txt" "interface: $IFACE" "show"
expect_contains "$RUNDIR/show-pretty.txt" "listening port: 51821" "show"
expect_contains "$RUNDIR/show-pretty.txt" "fwmark: 0x1234" "show"
expect_contains "$RUNDIR/show-pretty.txt" "advanced security: yes" "show"
expect_contains "$RUNDIR/show-pretty.txt" "advanced security: no" "show"
if [ "$(grep -c '^peer: ' "$RUNDIR/show-pretty.txt")" -ne 2 ]; then
    fail "show: ожидалось два пира"
fi
uwg_ok show-jc "$RUNDIR/show-jc.txt" show "$IFACE" jc
expect_contains "$RUNDIR/show-jc.txt" "4" "show jc"
uwg_ok show-h1 "$RUNDIR/show-h1.txt" show "$IFACE" h1
expect_contains "$RUNDIR/show-h1.txt" "1000-1010" "show h1"
uwg_ok show-i1 "$RUNDIR/show-i1.txt" show "$IFACE" i1
expect_contains "$RUNDIR/show-i1.txt" "<b 0x160d2f><c>" "show i1"
uwg_ok show-advsec "$RUNDIR/show-advsec.txt" show "$IFACE" advanced-security
expect_contains "$RUNDIR/show-advsec.txt" "$PEER1_PUB" "show advanced-security"
expect_contains "$RUNDIR/show-advsec.txt" "$PEER2_PUB" "show advanced-security"
if ! grep -Fq "$PEER1_PUB	yes" "$RUNDIR/show-advsec.txt"; then
    cat "$RUNDIR/show-advsec.txt" >&2
    fail "show advanced-security: у $PEER1_PUB ожидалось yes"
fi
if ! grep -Fq "$PEER2_PUB	no" "$RUNDIR/show-advsec.txt"; then
    cat "$RUNDIR/show-advsec.txt" >&2
    fail "show advanced-security: у $PEER2_PUB ожидалось no"
fi
uwg_ok show-allowed "$RUNDIR/show-allowed.txt" show "$IFACE" allowed-ips
for prefix in "10.99.0.0/24" "fd00::/64" "10.99.1.0/24"; do
    expect_contains "$RUNDIR/show-allowed.txt" "$prefix" "show allowed-ips"
done
printf 'show: OK\n'

printf '== addconf: пир добавляется, private key не сбрасывается ==\n'
cat >"$RUNDIR/peers-only.conf" <<EOF
[Peer]
PublicKey = $PEER3_PUB
AllowedIPs = 10.42.0.0/24
Endpoint = 192.0.2.55:51820
PersistentKeepalive = 15
AdvancedSecurity = on
EOF
uwg_ok addconf "$RUNDIR/addconf.out" addconf "$IFACE" "$RUNDIR/peers-only.conf"
uwg_ok showconf-after-addconf "$RUNDIR/showconf-after-addconf.txt" showconf "$IFACE"
expect_contains "$RUNDIR/showconf-after-addconf.txt" "PrivateKey = $PRIVATE" "addconf private key"
expect_contains "$RUNDIR/showconf-after-addconf.txt" "$PEER3_PUB" "addconf peer"
if [ "$(grep -c '^\[Peer\]' "$RUNDIR/showconf-after-addconf.txt")" -ne 3 ]; then
    fail "addconf: ожидалось три пира"
fi
uwg_ok show-advsec-addconf "$RUNDIR/show-advsec-addconf.txt" show "$IFACE" advanced-security
if ! grep -Fq "$PEER3_PUB	yes" "$RUNDIR/show-advsec-addconf.txt"; then
    cat "$RUNDIR/show-advsec-addconf.txt" >&2
    fail "addconf: у $PEER3_PUB ожидалось AdvancedSecurity = yes"
fi
printf 'addconf: OK\n'

printf '== set: advanced-security on/off и удаление пира ==\n'
uwg_ok set-advsec-off "$RUNDIR/set-advsec-off.out" set "$IFACE" peer "$PEER3_PUB" advanced-security off
uwg_ok show-advsec-off "$RUNDIR/show-advsec-off.txt" show "$IFACE" advanced-security
if ! grep -Fq "$PEER3_PUB	no" "$RUNDIR/show-advsec-off.txt"; then
    cat "$RUNDIR/show-advsec-off.txt" >&2
    fail "set advanced-security off: значение не применилось"
fi
uwg_ok set-advsec-on "$RUNDIR/set-advsec-on.out" set "$IFACE" peer "$PEER3_PUB" advanced-security on
uwg_ok show-advsec-on "$RUNDIR/show-advsec-on.txt" show "$IFACE" advanced-security
if ! grep -Fq "$PEER3_PUB	yes" "$RUNDIR/show-advsec-on.txt"; then
    cat "$RUNDIR/show-advsec-on.txt" >&2
    fail "set advanced-security on: значение не применилось"
fi
uwg_ok set-remove "$RUNDIR/set-remove.out" set "$IFACE" peer "$PEER3_PUB" remove
uwg_ok show-peers-after-remove "$RUNDIR/show-peers-after-remove.txt" show "$IFACE" peers
if grep -Fq "$PEER3_PUB" "$RUNDIR/show-peers-after-remove.txt"; then
    cat "$RUNDIR/show-peers-after-remove.txt" >&2
    fail "set remove: пир не удалён"
fi
if [ "$(wc -l <"$RUNDIR/show-peers-after-remove.txt")" -ne 2 ]; then
    fail "set remove: ожидалось два пира"
fi
uwg_ok set-add-peer "$RUNDIR/set-add-peer.out" set "$IFACE" peer "$PEER3_PUB" \
    allowed-ips 10.42.0.0/24 endpoint 192.0.2.55:51820 persistent-keepalive 15 advanced-security on
uwg_ok showconf-after-set "$RUNDIR/showconf-after-set.txt" showconf "$IFACE"
expect_contains "$RUNDIR/showconf-after-set.txt" "$PEER3_PUB" "set peer"
expect_contains "$RUNDIR/showconf-after-set.txt" "Endpoint = 192.0.2.55:51820" "set peer"
printf 'set: OK\n'

printf '== syncconf: удаляет пиров, которых нет в конфиге ==\n'
cat >"$RUNDIR/sync.conf" <<EOF
[Interface]
PrivateKey = $PRIVATE
ListenPort = 51821
FwMark = 0x1234
Jc = 4
Jmin = 50
Jmax = 1000
S1 = 15
S2 = 30
S3 = 45
S4 = 60
H1 = 1000-1010
H2 = 2000-2010
H3 = 3000-3010
H4 = 4000-4010
I1 = <b 0x160d2f><c>
I2 = <r 32>
I3 = <t>
I4 = <rc 16>
I5 = <rd 8>
HeaderProtectionKey = $HEADER_KEY
ContentPaddingAddition = 10-20
RekeyAfterTime = 100-120
RekeyTimeout = 5
RejectAfterTime = 180
KeepaliveTimeout = 10
MaxHandshakeAttempts = 18
RandomTrailers = on
DisableCookies = off

[Peer]
PublicKey = $PEER1_PUB
PresharedKey = $PSK
AllowedIPs = 10.99.0.0/24, fd00::/64
Endpoint = 192.0.2.10:51820
PersistentKeepalive = 25
AdvancedSecurity = on
EOF
uwg_ok syncconf "$RUNDIR/syncconf.out" syncconf "$IFACE" "$RUNDIR/sync.conf"
uwg_ok showconf-after-sync "$RUNDIR/showconf-after-sync.txt" showconf "$IFACE"
if grep -Fq "$PEER2_PUB" "$RUNDIR/showconf-after-sync.txt"; then
    cat "$RUNDIR/showconf-after-sync.txt" >&2
    fail "syncconf: пир $PEER2_PUB не удалён"
fi
if grep -Fq "$PEER3_PUB" "$RUNDIR/showconf-after-sync.txt"; then
    cat "$RUNDIR/showconf-after-sync.txt" >&2
    fail "syncconf: пир $PEER3_PUB не удалён"
fi
expect_contains "$RUNDIR/showconf-after-sync.txt" "PrivateKey = $PRIVATE" "syncconf private key"
if [ "$(grep -c '^\[Peer\]' "$RUNDIR/showconf-after-sync.txt")" -ne 1 ]; then
    fail "syncconf: ожидался один пир"
fi
printf 'syncconf: OK\n'

printf '== восстановление полного конфига ==\n'
uwg_ok setconf-final "$RUNDIR/setconf-final.out" setconf "$IFACE" "$RUNDIR/full.conf"
uwg_ok showconf-final "$RUNDIR/showconf-final.txt" showconf "$IFACE"
compare_configs "$RUNDIR/full.conf" "$RUNDIR/showconf-final.txt" "setconf после изменений"
printf 'восстановление: OK\n'

printf '== отрицательные проверки ==\n'
uwg_fails setconf-missing-file "fopen" setconf "$IFACE" "$RUNDIR/does-not-exist.conf"
uwg_fails show-unknown-parameter "Invalid parameter" show "$IFACE" bogus-parameter
printf 'отрицательные проверки: OK\n'

printf '== перезапуск демона ==\n'
cp "$RUNDIR/showconf-final.txt" "$RUNDIR/showconf-before-restart.txt"
stop_daemon
if ! wait_until 10 socket_absent; then
    fail "сокет $SOCK не удалён после остановки демона"
fi
uwg_fails show-stopped "Unable to access" show "$IFACE"
start_daemon
uwg_ok showconf-restarted "$RUNDIR/showconf-restarted.txt" showconf "$IFACE"
if grep -q '^\[Peer\]' "$RUNDIR/showconf-restarted.txt"; then
    cat "$RUNDIR/showconf-restarted.txt" >&2
    fail "после перезапуска демон не должен помнить пиров: состояние задаётся конфигом"
fi
uwg_ok setconf-restart "$RUNDIR/setconf-restart.out" setconf "$IFACE" "$RUNDIR/full.conf"
uwg_ok showconf-after-restart "$RUNDIR/showconf-after-restart.txt" showconf "$IFACE"
compare_configs "$RUNDIR/showconf-before-restart.txt" "$RUNDIR/showconf-after-restart.txt" "восстановление после перезапуска"
printf 'перезапуск: OK\n'

stop_daemon

if grep -q 'ERROR' "$RUNDIR/daemon.log"; then
    printf 'WARN: демон писал ERROR в лог (UAPI исправен, data path этим тестом не проверяется):\n' >&2
    grep 'ERROR' "$RUNDIR/daemon.log" | head -5 >&2
fi

printf 'PASS: e2e uwg ↔ umbrawg через UAPI (%s)\n' "$IFACE"
