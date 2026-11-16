#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Compares the numeric constants exposed by `src/constants.rs` with the
# UmbraWG kernel UAPI header.
#
# Usage: scripts/check-uapi-parity.sh [path/to/umbrawg.h]
#
# The header path can also be given with the UMBRAWG_UAPI environment
# variable. Without either, the default locations are tried: the kernel
# module source tree on the build server and the local host mirror.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: check-uapi-parity.sh [path/to/uapi/umbrawg.h]

Compares src/constants.rs with the UmbraWG UAPI header and exits non-zero
when a constant is missing or has a different value.
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
    usage
    exit 0
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
crate_root=$(dirname "$script_dir")
constants_file="$crate_root/src/constants.rs"

header=${1:-${UMBRAWG_UAPI:-}}
if [[ -z $header ]]; then
    for candidate in \
        /root/umbrawg/module/src/uapi/umbrawg.h \
        /var/tmp/umbrawg-src/umbrawg-linux-kernel-module/src/uapi/umbrawg.h
    do
        if [[ -f $candidate ]]; then
            header=$candidate
            break
        fi
    done
fi

if [[ -z $header ]]; then
    echo "error: UAPI header not found, pass it as an argument or set UMBRAWG_UAPI" >&2
    exit 2
fi
if [[ ! -f $header ]]; then
    echo "error: UAPI header not found: $header" >&2
    exit 2
fi
if [[ ! -f $constants_file ]]; then
    echo "error: crate constants not found: $constants_file" >&2
    exit 2
fi

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

read -r -d '' shared_awk <<'AWK' || true
function trim(s) {
    gsub(/^[ \t]+/, "", s)
    gsub(/[ \t]+$/, "", s)
    return s
}

function eval_expr(expr,   e, parts, n) {
    e = trim(expr)
    gsub(/[()]/, "", e)
    gsub(/[UuLl]/, "", e)
    gsub(/[ \t]/, "", e)
    if (e ~ /^[0-9]+<</) {
        n = split(e, parts, "<<")
        if (n != 2 || parts[2] !~ /^[0-9]+$/) {
            return ""
        }
        return (parts[1] + 0) * (2 ^ (parts[2] + 0))
    }
    if (e ~ /^[0-9]+$/) {
        return e + 0
    }
    return ""
}
AWK

awk "$shared_awk"'
function flush_define(line,   rest, eq_or_space) {
    rest = trim(line)
    match(rest, /^[A-Za-z_][A-Za-z0-9_]*/)
    if (RSTART != 1) {
        return
    }
    name = substr(rest, 1, RLENGTH)
    expr = trim(substr(rest, RLENGTH + 1))
    if (name !~ /^UWG_[A-Z0-9_]+$/ || expr == "") {
        return
    }
    value = eval_expr(expr)
    if (value != "") {
        print name, value
    }
}

{
    line = $0
    sub(/\/\/.*/, "", line)
    sub(/\/\*.*\*\//, "", line)
}

/^[ \t]*#[ \t]*define[ \t]+UWG_[A-Z0-9_]+[ \t]+/ {
    sub(/^[ \t]*#[ \t]*define[ \t]+/, "", line)
    flush_define(line)
    next
}

/^[ \t]*enum[ \t]+uwg/ {
    in_enum = 1
    last = -1
    cont = 0
    next
}

in_enum && /^[ \t]*}/ {
    in_enum = 0
    next
}

in_enum {
    if (cont) {
        cont = (line ~ /\|[ \t]*$/) ? 1 : 0
        next
    }
    text = trim(line)
    sub(/,$/, "", text)
    text = trim(text)
    if (text == "") {
        next
    }
    eq = index(text, "=")
    if (eq > 0) {
        name = trim(substr(text, 1, eq - 1))
        expr = trim(substr(text, eq + 1))
    } else {
        name = text
        expr = ""
    }
    if (name !~ /^[A-Z_][A-Z0-9_]*$/) {
        if (text ~ /\|[ \t]*$/) {
            cont = 1
        }
        next
    }
    if (expr == "") {
        value = last + 1
    } else {
        value = eval_expr(expr)
        if (value == "") {
            value = last + 1
        }
    }
    last = value
    if (name ~ /^__/) {
        if (text ~ /\|[ \t]*$/) {
            cont = 1
        }
        next
    }
    print name, value
    if (text ~ /\|[ \t]*$/) {
        cont = 1
    }
}
' "$header" | sort -u -k1,1 >"$work_dir/uapi.txt"

awk "$shared_awk"'
/^[ \t]*pub const / {
    text = $0
    sub(/^[ \t]*pub const[ \t]+/, "", text)
    sub(/;.*/, "", text)
    eq = index(text, "=")
    if (eq == 0) {
        next
    }
    decl = substr(text, 1, eq - 1)
    expr = substr(text, eq + 1)
    sub(/:.*/, "", decl)
    name = trim(decl)
    value = eval_expr(expr)
    if (value == "") {
        printf "error: unsupported value for %s: %s\n", name, trim(expr) > "/dev/stderr"
        exit 3
    }
    print name, value
}
' "$constants_file" | sort -u -k1,1 >"$work_dir/crate.txt"

if [[ ! -s $work_dir/crate.txt ]]; then
    echo "error: no constants parsed from $constants_file" >&2
    exit 2
fi
if [[ ! -s $work_dir/uapi.txt ]]; then
    echo "error: no constants parsed from $header" >&2
    exit 2
fi

echo "UAPI header: $header"
echo "crate file:  $constants_file"
echo

checked=0
missing=0
mismatched=0

while read -r name value; do
    header_value=$(awk -v name="$name" '$1 == name { print $2; exit }' "$work_dir/uapi.txt")
    checked=$((checked + 1))
    if [[ -z $header_value ]]; then
        printf 'MISSING   %-48s crate=%s\n' "$name" "$value"
        missing=$((missing + 1))
    elif [[ $header_value -ne $value ]]; then
        printf 'MISMATCH  %-48s crate=%s uapi=%s\n' "$name" "$value" "$header_value"
        mismatched=$((mismatched + 1))
    else
        printf 'ok        %-48s %s\n' "$name" "$value"
    fi
done <"$work_dir/crate.txt"

echo
echo "checked: $checked, mismatched: $mismatched, missing: $missing"

if [[ $mismatched -ne 0 || $missing -ne 0 ]]; then
    echo "error: crate constants do not match the UAPI header" >&2
    exit 1
fi

echo "crate constants match the UAPI header"
