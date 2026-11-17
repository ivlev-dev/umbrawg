#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tools_dir="$(cd "$script_dir/../.." && pwd)"
out_dir="$tools_dir/dist"

archive="$("$script_dir/make-dist.sh")"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$tools_dir/Cargo.toml" | head -n1)"

top="$(mktemp -d)"
trap 'rm -rf "$top"' EXIT

mkdir -p "$top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
cp "$archive" "$top/SOURCES/tools-v${version}.tar.gz"
sed "s/^Version:.*/Version:        $version/" \
    "$tools_dir/umbrawg-tools.spec" > "$top/SPECS/umbrawg-tools.spec"

rpmbuild --define "_topdir $top" -ba "$top/SPECS/umbrawg-tools.spec"

mkdir -p "$out_dir"
find "$top/RPMS" "$top/SRPMS" -type f -name '*.rpm' -exec cp -t "$out_dir" {} +
echo "$out_dir/umbrawg-tools-${version}-*.rpm"
