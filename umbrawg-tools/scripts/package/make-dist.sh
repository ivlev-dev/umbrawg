#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tools_dir="$(cd "$script_dir/../.." && pwd)"
netlink_dir="$(cd "$tools_dir/.." && pwd)/netlink-packet-umbrawg"
out_dir="$tools_dir/dist"

version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$tools_dir/Cargo.toml" | head -n1)"
if [[ -z "$version" ]]; then
    echo "error: cannot determine workspace version" >&2
    exit 1
fi
if [[ ! -f "$netlink_dir/Cargo.toml" ]]; then
    echo "error: $netlink_dir not found" >&2
    exit 1
fi

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

mkdir -p "$out_dir" "$stage/umbrawg-tools" "$stage/netlink-packet-umbrawg"

tar -C "$tools_dir" \
    --exclude=.git \
    --exclude=target \
    --exclude=dist \
    --exclude=.tmp \
    --exclude=legacy-c/wg-quick/awg \
    --exclude=contrib \
    --exclude=bench \
    --exclude='*.deb' \
    --exclude='*.rpm' \
    -cf - . | tar -C "$stage/umbrawg-tools" -xf -

tar -C "$netlink_dir" \
    --exclude=.git \
    --exclude=target \
    -cf - . | tar -C "$stage/netlink-packet-umbrawg" -xf -

archive="$out_dir/umbrawg-tools-$version.tar.gz"
tar -C "$stage" -czf "$archive" umbrawg-tools netlink-packet-umbrawg
echo "$archive"
