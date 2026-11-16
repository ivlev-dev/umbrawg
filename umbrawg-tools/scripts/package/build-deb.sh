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
archive="$("$script_dir/make-dist.sh")"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

tar -C "$work" -xzf "$archive"
cd "$work/umbrawg-tools"
dpkg-buildpackage -b -us -uc

mkdir -p "$out_dir"
find "$work" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.buildinfo' -o -name '*.changes' \) \
    -exec cp -t "$out_dir" {} +
echo "$out_dir/umbrawg-tools_${version}_*.deb"
