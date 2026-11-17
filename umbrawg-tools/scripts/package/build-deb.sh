#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tools_dir="$(cd "$script_dir/../.." && pwd)"
out_dir="$tools_dir/dist"

version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$tools_dir/Cargo.toml" | head -n1)"
changelog_version="$(sed -n '1s/.*(\(.*\)).*/\1/p' "$tools_dir/debian/changelog")"
if [[ "$changelog_version" != "$version" ]]; then
    echo "error: debian/changelog is $changelog_version but Cargo workspace is $version" >&2
    exit 1
fi
rust_version="$(sed -n 's/^rust-version = "\(.*\)"/\1/p' "$tools_dir/Cargo.toml" | head -n1)"
archive="$("$script_dir/make-dist.sh")"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

tar -C "$work" -xzf "$archive"
cd "$work/umbrawg-tools"

build_flags=(-b -us -uc)
if ! dpkg-checkbuilddeps >/dev/null 2>&1; then
    for tool in cargo rustc dh dpkg-buildpackage; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "error: $tool not found; install the Build-Depends from debian/control" >&2
            exit 1
        fi
    done
    actual_rust="$(rustc --version | awk '{print $2}')"
    if [[ -n "$rust_version" ]] && [[ "$(printf '%s\n%s\n' "$actual_rust" "$rust_version" | sort -V | head -n1)" != "$rust_version" ]]; then
        echo "error: rustc $actual_rust is older than rust-version $rust_version" >&2
        exit 1
    fi
    echo "warning: Build-Depends are not installed as distribution packages" >&2
    echo "warning: using the toolchain from PATH (rustc $actual_rust), passing -d to dpkg-buildpackage" >&2
    build_flags+=(-d)
fi
dpkg-buildpackage "${build_flags[@]}"

mkdir -p "$out_dir"
find "$work" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.buildinfo' -o -name '*.changes' \) \
    -exec cp -t "$out_dir" {} +
echo "$out_dir/umbrawg-tools_${version}_*.deb"
