#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tools_dir="$(cd "$script_dir/.." && pwd)"
cd "$tools_dir"

UWG_BIN="${UWG:-target/release/uwg}"
if [ ! -x "$UWG_BIN" ] && [ -x "$tools_dir/$UWG_BIN" ]; then
    UWG_BIN="$tools_dir/$UWG_BIN"
fi
if [ ! -x "$UWG_BIN" ]; then
    printf 'FAIL: бинарник uwg не найден или не исполняем: %s\n' "$UWG_BIN" >&2
    exit 1
fi

failures=0
missing=()

bad() {
    printf 'FAIL: %s\n' "$*" >&2
    missing+=("$*")
    failures=$((failures + 1))
}

# Разбор списка подкоманд из вывода uwg --help (с запасными вариантами).
parse_commands() {
    local out parsed
    for invocation in "--help" "-h" "help"; do
        out="$("$UWG_BIN" $invocation 2>&1 || true)"
        parsed="$(printf '%s\n' "$out" | awk '
            BEGIN { in_cmds = 0 }
            /^Commands:/ { in_cmds = 1; next }
            /^(Options|OPTIONS|Global options|SUBCOMMANDS):/ { in_cmds = 0 }
            in_cmds && /^  [A-Za-z]/ { print $1 }
        ')"
        if [ -n "$parsed" ]; then
            printf '%s\n' "$parsed"
            return 0
        fi
    done
    # Запасной вариант: сообщение об ошибке usage.
    out="$("$UWG_BIN" __definitely_unknown_subcommand__ 2>&1 || true)"
    parsed="$(printf '%s\n' "$out" | awk '
        BEGIN { in_cmds = 0 }
        /^Commands:/ { in_cmds = 1; next }
        /^(Options|OPTIONS|Usage):/ { in_cmds = 0 }
        in_cmds && /^  [A-Za-z]/ { print $1 }
    ')"
    if [ -n "$parsed" ]; then
        printf '%s\n' "$parsed"
        return 0
    fi
    return 1
}

commands="$(parse_commands)" || {
    printf 'FAIL: не удалось разобрать список подкоманд из uwg --help\n' >&2
    exit 1
}
if [ -z "$commands" ]; then
    printf 'FAIL: список подкоманд пуст\n' >&2
    exit 1
fi

# Параметры show — полный список из show_usage (crates/uwg/src/cli.rs).
read -r -d '' params_str <<'EOF' || true
public-key
private-key
listen-port
fwmark
peers
preshared-keys
endpoints
allowed-ips
latest-handshakes
transfer
persistent-keepalive
advanced-security
dump
jc
jmin
jmax
s1
s2
s3
s4
h1
h2
h3
h4
i1
i2
i3
i4
i5
header-protection-key
content-padding-addition
rekey-after-time
rekey-timeout
reject-after-time
keepalive-timeout
max-handshake-attempts
max_handshake_attempts
random-trailers
disable-cookies
EOF
params=()
while IFS= read -r line; do
    [ -z "$line" ] && continue
    params+=("$line")
done <<< "$params_str"

quick_commands=(up down save strip)

uwg_man="man/uwg.8"
uwg_completions=(completions/_uwg completions/uwg.bash completions/uwg.fish)
quick_man="man/uwg-quick.8"
quick_completions=(completions/_uwg-quick completions/uwg-quick.bash completions/uwg-quick.fish)

# Проверка подкоманд uwg.
for cmd in $commands; do
    # man: команда оформлена как \fBcmd\fP
    if ! grep -Fq "\\fB${cmd}\\fP" "$uwg_man"; then
        bad "man/uwg.8: нет подкоманды '$cmd'"
    fi
    for f in "${uwg_completions[@]}"; do
        if ! grep -Eq "(^|[^[:alnum:]_-])${cmd}([^[:alnum:]_-]|\$)" "$f"; then
            bad "$f: нет подкоманды '$cmd'"
        fi
    done
done

# Проверка параметров show.
for param in "${params[@]}"; do
    if ! grep -Fq "$param" "$uwg_man"; then
        bad "man/uwg.8: нет параметра show '$param'"
    fi
    for f in "${uwg_completions[@]}"; do
        if ! grep -Fq "$param" "$f"; then
            bad "$f: нет параметра show '$param'"
        fi
    done
done

# Проверка подкоманд uwg-quick.
for cmd in "${quick_commands[@]}"; do
    if ! grep -Fq "\\fB${cmd}\\fP" "$quick_man"; then
        bad "man/uwg-quick.8: нет подкоманды '$cmd'"
    fi
    for f in "${quick_completions[@]}"; do
        if ! grep -Fq "$cmd" "$f"; then
            bad "$f: нет подкоманды '$cmd'"
        fi
    done
done

if [ "$failures" -ne 0 ]; then
    printf '\nDOCS CHECK: FAIL (%d проблем)\n' "$failures" >&2
    printf 'Отсутствующие пункты:\n' >&2
    for m in "${missing[@]}"; do
        printf '  - %s\n' "$m" >&2
    done
    exit 1
fi

printf 'DOCS CHECK: OK\n'
printf 'Подкоманд uwg: %s\n' "$(printf '%s ' $commands)"
printf 'Параметров show: %d\n' "${#params[@]}"
printf 'Подкоманд uwg-quick: %s\n' "${quick_commands[*]}"
