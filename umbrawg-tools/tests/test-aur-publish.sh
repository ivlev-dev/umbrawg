#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
publish="$repo_root/scripts/aur-publish.sh"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/aur-publish-test.XXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT

passed=0
failed=0
log="$tmp/output.log"

pass() {
    passed=$((passed + 1))
    printf 'ok: %s\n' "$1"
}

fail() {
    failed=$((failed + 1))
    printf 'FAIL: %s\n' "$1" >&2
}

expect_exit() {
    local expected=$1 name=$2 rc
    shift 2
    set +e
    "$@" >"$log" 2>&1
    rc=$?
    set -e
    if [ "$rc" -eq "$expected" ]; then
        pass "$name (код $rc)"
    else
        fail "$name: ожидался код $expected, получен $rc"
        sed 's/^/    /' "$log" >&2
    fi
}

check_true() {
    local name=$1
    shift
    if "$@"; then
        pass "$name"
    else
        fail "$name"
        sed 's/^/    /' "$log" >&2 || true
    fi
}

check_log() {
    local name=$1 text=$2
    if grep -qF -- "$text" "$log"; then
        pass "$name"
    else
        fail "$name: в выводе нет '$text'"
        sed 's/^/    /' "$log" >&2
    fi
}

make_pkg() {
    local name=$1 ver=$2 sums=$3 with_install=${4:-0} dir
    dir="$src/contrib/arch/$name"
    mkdir -p "$dir"
    cat >"$dir/PKGBUILD" <<EOF
pkgname=$name
pkgver=$ver
pkgrel=1
pkgdesc="test package"
arch=('any')
url="https://example.invalid/$name"
license=('MIT')
sha256sums=('$sums')

package() {
  install -d "\$pkgdir/usr/share/$name"
}
EOF
    if [ "$with_install" = 1 ]; then
        printf 'install=%s.install\n' "$name" >>"$dir/PKGBUILD"
        printf 'post_install() {\n  :\n}\n' >"$dir/$name.install"
    fi
    if command -v makepkg >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
        (cd "$dir" && makepkg --printsrcinfo >.SRCINFO)
    else
        {
            printf 'pkgbase = %s\n' "$name"
            printf '\tpkgdesc = test package\n'
            printf '\tpkgver = %s\n' "$ver"
            printf '\tpkgrel = 1\n'
            printf '\turl = https://example.invalid/%s\n' "$name"
            printf '\tarch = any\n'
            printf '\tlicense = MIT\n'
            if [ "$with_install" = 1 ]; then
                printf '\tinstall = %s.install\n' "$name"
            fi
            printf '\tsha256sums = %s\n' "$sums"
            printf '\n'
            printf 'pkgname = %s\n' "$name"
        } >"$dir/.SRCINFO"
    fi
}

count_commits() {
    git --git-dir="$1" rev-list --all --count 2>/dev/null || printf '0'
}

git_env=(
    GIT_AUTHOR_NAME="AUR Test"
    GIT_AUTHOR_EMAIL="aur-test@example.invalid"
    GIT_COMMITTER_NAME="AUR Test"
    GIT_COMMITTER_EMAIL="aur-test@example.invalid"
)

src="$tmp/src"
aur="$tmp/aur"
workdir="$tmp/work"
mkdir -p "$aur"
git init --bare -q "$aur/umbrawg-tools.git"

make_pkg umbrawg-tools 1.2.3 SKIP 1

expect_exit 0 "dry-run проходит" \
    env AUR_BASE="file://$aur" "$publish" --source-root "$src" --workdir "$workdir" umbrawg-tools
check_log "dry-run печатает clone" "git clone file://$aur/umbrawg-tools.git"
check_log "dry-run печатает commit" "commit -m 'Update to 1.2.3-1'"
check_log "dry-run печатает push" "push origin HEAD:master"
check_log "dry-run печатает копирование .install" "umbrawg-tools.install"
check_true "dry-run не создаёт коммитов" test "$(count_commits "$aur/umbrawg-tools.git")" = 0
check_true "dry-run не создаёт workdir" test ! -e "$workdir"
check_true "dry-run не копирует файлы" test ! -e "$aur/umbrawg-tools.git/PKGBUILD"

expect_exit 0 "push свежего пакета проходит" \
    env AUR_BASE="file://$aur" "${git_env[@]}" "$publish" --source-root "$src" --workdir "$workdir" --push umbrawg-tools
check_log "push сообщает о публикации" "опубликовано: umbrawg-tools 1.2.3-1"
check_true "push создал один коммит" test "$(count_commits "$aur/umbrawg-tools.git")" = 1
check_true "коммит содержит PKGBUILD" \
    bash -c "git --git-dir='$aur/umbrawg-tools.git' ls-tree --name-only master | grep -qx PKGBUILD"
check_true "коммит содержит .SRCINFO" \
    bash -c "git --git-dir='$aur/umbrawg-tools.git' ls-tree --name-only master | grep -qx .SRCINFO"
check_true "коммит содержит .install" \
    bash -c "git --git-dir='$aur/umbrawg-tools.git' ls-tree --name-only master | grep -qx umbrawg-tools.install"
check_true "сообщение коммита верное" \
    test "$(git --git-dir="$aur/umbrawg-tools.git" log -1 --format=%s master)" = "Update to 1.2.3-1"
check_true "PKGBUILD в AUR совпадает с источником" \
    bash -c "git --git-dir='$aur/umbrawg-tools.git' show master:PKGBUILD | diff -u '$src/contrib/arch/umbrawg-tools/PKGBUILD' - >/dev/null"

expect_exit 0 "повторный push без изменений проходит" \
    env AUR_BASE="file://$aur" "${git_env[@]}" "$publish" --source-root "$src" --workdir "$workdir" --push umbrawg-tools
check_log "повторный push сообщает об отсутствии изменений" "изменений нет"
check_true "повторный push не создаёт коммит" test "$(count_commits "$aur/umbrawg-tools.git")" = 1

make_pkg umbrawg-daemon 1.2.3 TODO_UPDPKGSUMS_AFTER_FIRST_TAG
expect_exit 1 "отказ на заглушке TODO_UPDPKGSUMS" \
    env AUR_BASE="file://$aur" "$publish" --source-root "$src" --push umbrawg-daemon
check_log "отказ объясняет причину" "TODO_UPDPKGSUMS_AFTER_FIRST_TAG"
check_log "отказ предлагает updpkgsums" "updpkgsums"
check_true "заглушка не создаёт AUR-репозиторий" test ! -e "$aur/umbrawg-daemon.git"

mkdir -p "$src/contrib/arch/rust-netlink-packet-umbrawg"
printf 'pkgbase = rust-netlink-packet-umbrawg\n\tpkgver = 1.2.3\n\tpkgrel = 1\n\npkgname = rust-netlink-packet-umbrawg\n' \
    >"$src/contrib/arch/rust-netlink-packet-umbrawg/.SRCINFO"
expect_exit 1 "отказ при отсутствии PKGBUILD" \
    env AUR_BASE="file://$aur" "$publish" --source-root "$src" --push rust-netlink-packet-umbrawg
check_log "отказ называет отсутствующий файл" "нет PKGBUILD"

expect_exit 2 "ошибка git при недоступном AUR" \
    env AUR_BASE="file://$tmp/missing" "${git_env[@]}" "$publish" --source-root "$src" --push umbrawg-tools
check_log "ошибка git сообщает о clone" "git clone"

src_all="$tmp/src-all"
src="$src_all"
mkdir -p "$src_all/contrib/arch"
for name in umbrawg-tools umbrawg-tools-git umbrawg-dkms umbrawg-dkms-git \
    umbrawg-daemon umbrawg-daemon-git rust-netlink-packet-umbrawg rust-netlink-packet-umbrawg-git; do
    make_pkg "$name" 1.2.3 SKIP
done
workdir_all="$tmp/work-all"
expect_exit 0 "--all в dry-run проходит" \
    env AUR_BASE="file://$aur" "$publish" --all --source-root "$src_all" --workdir "$workdir_all"
for name in umbrawg-tools umbrawg-tools-git umbrawg-dkms umbrawg-dkms-git \
    umbrawg-daemon umbrawg-daemon-git rust-netlink-packet-umbrawg rust-netlink-packet-umbrawg-git; do
    check_log "--all упоминает $name" "dry-run: $name ->"
done
check_true "--all не создаёт workdir" test ! -e "$workdir_all"

printf 'итог: пройдено %s, провалено %s\n' "$passed" "$failed"
if [ "$failed" -ne 0 ]; then
    exit 1
fi
exit 0
