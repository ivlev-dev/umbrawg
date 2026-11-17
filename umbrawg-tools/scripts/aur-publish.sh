#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tools_root="$(cd "$script_dir/.." && pwd)"

AUR_BASE="${AUR_BASE:-ssh://aur@aur.archlinux.org}"
AUR_BASE="${AUR_BASE%/}"

packages=(
    umbrawg-tools
    umbrawg-tools-git
    umbrawg-dkms
    umbrawg-dkms-git
    umbrawg-daemon
    umbrawg-daemon-git
    rust-netlink-packet-umbrawg
    rust-netlink-packet-umbrawg-git
)

usage() {
    cat <<'EOF'
Использование: aur-publish.sh [--all | <пакет>] [--push]
                              [--source-root <каталог>]... [--workdir <каталог>]

Копирует PKGBUILD, *.install и .SRCINFO из contrib/arch/<пакет>/ в
AUR-репозиторий и коммитит обновление.

Аргументы:
  <пакет>                 имя пакета AUR (например, umbrawg-tools)
  --all                   обработать все 8 пакетов
  --push                  выполнить публикацию (по умолчанию dry-run)
  --source-root <каталог> корень репозитория с contrib/arch; можно повторять
  --workdir <каталог>     каталог для временного клона AUR
  -h, --help              показать справку

Переменные окружения:
  AUR_BASE                база AUR (по умолчанию ssh://aur@aur.archlinux.org)
  UMBRAWG_TOOLS_DIR       корень repo tools
  UMBRAWG_MODULE_DIR      корень repo модуля ядра
  UMBRAWG_RUST_DIR        корень repo демона
  UMBRAWG_NETLINK_DIR     корень repo netlink-крейта

Коды возврата: 0 — успех, 1 — ошибка валидации, 2 — ошибка git или сети.
EOF
}

errors=0
status=0
cleanup_paths=()

cleanup() {
    local path
    if [ "${#cleanup_paths[@]}" -eq 0 ]; then
        return 0
    fi
    for path in "${cleanup_paths[@]}"; do
        rm -rf -- "$path"
    done
}
trap cleanup EXIT

shell_quote() {
    local value=$1
    if [[ $value =~ ^[A-Za-z0-9_./:@%+=,-]+$ ]]; then
        printf '%s' "$value"
    else
        printf "'%s'" "${value//\'/\'\\\'\'}"
    fi
}

package_key() {
    case "$1" in
        umbrawg-tools|umbrawg-tools-git) printf 'tools\n' ;;
        umbrawg-dkms|umbrawg-dkms-git) printf 'module\n' ;;
        umbrawg-daemon|umbrawg-daemon-git) printf 'rust\n' ;;
        rust-netlink-packet-umbrawg|rust-netlink-packet-umbrawg-git) printf 'netlink\n' ;;
        *) return 1 ;;
    esac
}

root_env() {
    case "$1" in
        tools) printf 'UMBRAWG_TOOLS_DIR\n' ;;
        module) printf 'UMBRAWG_MODULE_DIR\n' ;;
        rust) printf 'UMBRAWG_RUST_DIR\n' ;;
        netlink) printf 'UMBRAWG_NETLINK_DIR\n' ;;
        *) return 1 ;;
    esac
}

root_candidates() {
    case "$1" in
        tools)
            printf '%s\n' "/root/umbrawg/tools" "$tools_root"
            ;;
        module)
            printf '%s\n' \
                "/root/umbrawg/module" \
                "/root/umbrawg/umbrawg-linux-kernel-module" \
                "$tools_root/../umbrawg-linux-kernel-module" \
                "$tools_root/../module" \
                "$tools_root/../module-master"
            ;;
        rust)
            printf '%s\n' \
                "/root/umbrawg/rust" \
                "/root/umbrawg/umbrawg-rs" \
                "$tools_root/../umbrawg-rs" \
                "$tools_root/../rust" \
                "$tools_root/../rust-parallel-rx"
            ;;
        netlink)
            printf '%s\n' \
                "/root/umbrawg/netlink" \
                "/root/umbrawg/netlink-packet-umbrawg" \
                "$tools_root/../netlink-packet-umbrawg" \
                "$tools_root/../netlink"
            ;;
    esac
}

resolve_root() {
    local key=$1 env_name env_value candidate
    env_name="$(root_env "$key")"
    env_value="${!env_name:-}"
    if [ -n "$env_value" ]; then
        if [ ! -d "$env_value/contrib/arch" ]; then
            printf 'ошибка: %s=%s, нет каталога contrib/arch\n' "$env_name" "$env_value" >&2
            return 1
        fi
        (cd "$env_value" && pwd)
        return 0
    fi
    while IFS= read -r candidate; do
        if [ -d "$candidate/contrib/arch" ]; then
            (cd "$candidate" && pwd)
            return 0
        fi
    done < <(root_candidates "$key")
    printf 'ошибка: не найден корень репозитория (%s), задайте %s\n' "$key" "$env_name" >&2
    return 1
}

find_pkgdir() {
    local pkg=$1 root seen=""
    for root in "${roots[@]}"; do
        case " $seen " in
            *" $root "*) continue ;;
        esac
        seen="$seen $root"
        if [ -d "$root/contrib/arch/$pkg" ]; then
            (cd "$root/contrib/arch/$pkg" && pwd)
            return 0
        fi
    done
    return 1
}

validate_pkg() {
    local pkg=$1 pkgdir=$2
    local pkgbuild="$pkgdir/PKGBUILD" srcinfo="$pkgdir/.SRCINFO"
    local pkgbase pkgver pkgrel tmpdir expected diffout

    if [ ! -f "$pkgbuild" ]; then
        printf 'ошибка: %s: нет PKGBUILD\n' "$pkgdir" >&2
        return 1
    fi
    if [ ! -f "$srcinfo" ]; then
        printf 'ошибка: %s: нет .SRCINFO\n' "$pkgdir" >&2
        return 1
    fi

    pkgbase="$(sed -n 's/^pkgbase = //p' "$srcinfo" | head -n1)"
    if [ "$pkgbase" != "$pkg" ]; then
        printf 'ошибка: %s: pkgbase=%s, ожидался %s\n' "$srcinfo" "${pkgbase:-<пусто>}" "$pkg" >&2
        return 1
    fi

    pkgver="$(sed -n 's/^[[:space:]]*pkgver = //p' "$srcinfo" | head -n1)"
    pkgrel="$(sed -n 's/^[[:space:]]*pkgrel = //p' "$srcinfo" | head -n1)"
    if [ -z "$pkgver" ]; then
        printf 'ошибка: %s: не удалось извлечь pkgver\n' "$srcinfo" >&2
        return 1
    fi
    if [[ ! $pkgrel =~ ^[0-9]+$ ]]; then
        printf 'ошибка: %s: не удалось извлечь pkgrel (%s)\n' "$srcinfo" "${pkgrel:-<пусто>}" >&2
        return 1
    fi

    if [[ $pkg != *-git ]] && grep -q 'TODO_UPDPKGSUMS' "$pkgbuild" "$srcinfo"; then
        printf 'ошибка: %s: стабильный пакет содержит заглушку TODO_UPDPKGSUMS_AFTER_FIRST_TAG\n' "$pkg" >&2
        printf '        после публикации тегов выполните updpkgsums и makepkg --printsrcinfo > .SRCINFO\n' >&2
        return 1
    fi

    if command -v makepkg >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
        tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aur-srcinfo.XXXXXX")"
        expected="$tmpdir/.SRCINFO"
        diffout="$tmpdir/diff"
        if ! (cd "$pkgdir" && makepkg --printsrcinfo) >"$expected" 2>"$tmpdir/err"; then
            printf 'ошибка: %s: makepkg --printsrcinfo завершился с ошибкой\n' "$pkg" >&2
            sed 's/^/        /' "$tmpdir/err" >&2
            rm -rf -- "$tmpdir"
            return 1
        fi
        if ! diff -u "$srcinfo" "$expected" >"$diffout"; then
            printf 'ошибка: %s: .SRCINFO не совпадает с makepkg --printsrcinfo\n' "$pkg" >&2
            sed 's/^/        /' "$diffout" >&2
            printf '        обновите файл: (cd %s && makepkg --printsrcinfo > .SRCINFO)\n' "$pkgdir" >&2
            rm -rf -- "$tmpdir"
            return 1
        fi
        rm -rf -- "$tmpdir"
    fi

    printf 'ok: %s %s-%s (%s)\n' "$pkg" "$pkgver" "$pkgrel" "$pkgdir"
    return 0
}

pkgver_of() {
    local srcinfo=$1
    local pkgver pkgrel
    pkgver="$(sed -n 's/^[[:space:]]*pkgver = //p' "$srcinfo" | head -n1)"
    pkgrel="$(sed -n 's/^[[:space:]]*pkgrel = //p' "$srcinfo" | head -n1)"
    printf '%s %s\n' "$pkgver" "$pkgrel"
}

aur_url_of() {
    printf '%s/%s.git\n' "$AUR_BASE" "$1"
}

dry_run_pkg() {
    local pkg=$1 pkgdir=$2 clone_base clone_url file version commit_msg
    clone_base="${workdir:-${TMPDIR:-/tmp}}/aur-publish-${pkg}"
    clone_url="$(aur_url_of "$pkg")"
    version="$(pkgver_of "$pkgdir/.SRCINFO")"
    commit_msg="Update to ${version// /-}"

    printf 'dry-run: %s -> %s\n' "$pkg" "$clone_url"
    printf '  git clone %s %s\n' "$(shell_quote "$clone_url")" "$(shell_quote "$clone_base")"
    for file in "$pkgdir/PKGBUILD" "$pkgdir/.SRCINFO" "$pkgdir"/*.install; do
        if [ ! -e "$file" ]; then
            continue
        fi
        printf '  install -m0644 %s %s\n' \
            "$(shell_quote "$file")" \
            "$(shell_quote "$clone_base/$(basename "$file")")"
    done
    printf '  git -C %s add -A\n' "$(shell_quote "$clone_base")"
    printf '  git -C %s commit -m %s\n' "$(shell_quote "$clone_base")" "$(shell_quote "$commit_msg")"
    printf '  git -C %s push origin HEAD:master\n' "$(shell_quote "$clone_base")"
    return 0
}

git_fail() {
    printf 'ошибка: %s\n' "$*" >&2
    return 2
}

publish_pkg() {
    local pkg=$1 pkgdir=$2 tmpbase tmpdir clone clone_url file base version commit_msg
    tmpbase="${workdir:-${TMPDIR:-/tmp}}"
    clone_url="$(aur_url_of "$pkg")"
    version="$(pkgver_of "$pkgdir/.SRCINFO")"
    commit_msg="Update to ${version// /-}"

    if [ -n "$workdir" ] && [ ! -d "$workdir" ]; then
        if ! mkdir -p -- "$workdir"; then
            git_fail "не удалось создать workdir $workdir"
            return 2
        fi
    fi
    tmpdir="$(mktemp -d "$tmpbase/${pkg}.XXXXXX")" || {
        git_fail "не удалось создать временный каталог в $tmpbase"
        return 2
    }
    cleanup_paths+=("$tmpdir")
    clone="$tmpdir/$pkg"

    printf 'push: %s -> %s\n' "$pkg" "$clone_url"
    if ! git clone "$clone_url" "$clone"; then
        git_fail "git clone $clone_url"
        return 2
    fi
    if ! git -C "$clone" rev-parse --verify -q HEAD >/dev/null 2>&1; then
        if ! git -C "$clone" symbolic-ref HEAD refs/heads/master; then
            git_fail "не удалось подготовить ветку master в $clone"
            return 2
        fi
    fi

    if ! install -m0644 "$pkgdir/PKGBUILD" "$clone/PKGBUILD"; then
        git_fail "не удалось скопировать PKGBUILD"
        return 2
    fi
    if ! install -m0644 "$pkgdir/.SRCINFO" "$clone/.SRCINFO"; then
        git_fail "не удалось скопировать .SRCINFO"
        return 2
    fi
    for file in "$pkgdir"/*.install; do
        if [ ! -e "$file" ]; then
            continue
        fi
        if ! install -m0644 "$file" "$clone/$(basename "$file")"; then
            git_fail "не удалось скопировать $(basename "$file")"
            return 2
        fi
    done
    for file in "$clone"/*.install; do
        if [ ! -e "$file" ]; then
            continue
        fi
        base="$(basename "$file")"
        if [ ! -e "$pkgdir/$base" ]; then
            rm -f -- "$file"
        fi
    done

    if ! git -C "$clone" add -A; then
        git_fail "git add в $clone"
        return 2
    fi
    if git -C "$clone" diff --cached --quiet; then
        printf 'изменений нет: %s %s\n' "$pkg" "${version// /-}"
        return 0
    fi
    if ! git -C "$clone" commit -q -m "$commit_msg"; then
        git_fail "git commit не удался, проверьте user.name и user.email"
        return 2
    fi
    if ! git -C "$clone" push origin HEAD:master; then
        git_fail "git push $clone_url"
        return 2
    fi
    printf 'опубликовано: %s %s\n' "$pkg" "${version// /-}"
    return 0
}

process_pkg() {
    local pkg=$1 pkgdir rc=0
    if ! pkgdir="$(find_pkgdir "$pkg")"; then
        printf 'ошибка: не найден contrib/arch/%s ни в одном source root\n' "$pkg" >&2
        printf '        корни: %s\n' "${roots[*]}" >&2
        return 1
    fi
    if ! validate_pkg "$pkg" "$pkgdir"; then
        return 1
    fi
    if [ "$do_push" = 1 ]; then
        publish_pkg "$pkg" "$pkgdir" || rc=$?
    else
        dry_run_pkg "$pkg" "$pkgdir" || rc=$?
    fi
    return "$rc"
}

do_push=0
do_all=0
package=""
workdir=""
explicit_roots=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --push)
            do_push=1
            ;;
        --all)
            do_all=1
            ;;
        --source-root)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                printf 'ошибка: --source-root требует каталог\n' >&2
                exit 1
            fi
            explicit_roots+=("$2")
            shift
            ;;
        --workdir)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                printf 'ошибка: --workdir требует каталог\n' >&2
                exit 1
            fi
            workdir=$2
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            while [ "$#" -gt 0 ]; do
                if [ -n "$package" ]; then
                    printf 'ошибка: лишний аргумент: %s\n' "$1" >&2
                    exit 1
                fi
                package=$1
                shift
            done
            break
            ;;
        -*)
            printf 'ошибка: неизвестный аргумент: %s\n' "$1" >&2
            usage >&2
            exit 1
            ;;
        *)
            if [ -n "$package" ]; then
                printf 'ошибка: лишний аргумент: %s\n' "$1" >&2
                exit 1
            fi
            package=$1
            ;;
    esac
    shift
done

if [ "$do_all" = 1 ] && [ -n "$package" ]; then
    printf 'ошибка: --all не сочетается с именем пакета\n' >&2
    exit 1
fi
if [ "$do_all" = 0 ] && [ -z "$package" ]; then
    printf 'ошибка: укажите имя пакета или --all\n' >&2
    usage >&2
    exit 1
fi

roots=()
if [ "${#explicit_roots[@]}" -gt 0 ]; then
    for root in "${explicit_roots[@]}"; do
        if [ ! -d "$root/contrib/arch" ]; then
            printf 'ошибка: %s: нет каталога contrib/arch\n' "$root" >&2
            exit 1
        fi
        roots+=("$(cd "$root" && pwd)")
    done
elif [ "$do_all" = 1 ]; then
    for key in tools module rust netlink; do
        if ! root="$(resolve_root "$key")"; then
            exit 1
        fi
        roots+=("$root")
    done
else
    if ! key="$(package_key "$package")"; then
        printf 'ошибка: неизвестный пакет: %s\n' "$package" >&2
        exit 1
    fi
    if ! root="$(resolve_root "$key")"; then
        exit 1
    fi
    roots+=("$root")
fi

printf 'AUR_BASE: %s\n' "$AUR_BASE"
printf 'режим: %s\n' "$([ "$do_push" = 1 ] && printf 'push' || printf 'dry-run')"
printf 'source roots:\n'
for root in "${roots[@]}"; do
    printf '  %s\n' "$root"
done

if [ "$do_all" = 1 ]; then
    selected=("${packages[@]}")
else
    selected=("$package")
fi

for pkg in "${selected[@]}"; do
    if process_pkg "$pkg"; then
        :
    else
        rc=$?
        errors=$((errors + 1))
        if [ "$rc" -gt "$status" ]; then
            status=$rc
        fi
    fi
done

if [ "${#selected[@]}" -gt 1 ]; then
    printf 'итог: пакетов %s, ошибок %s\n' "${#selected[@]}" "$errors"
fi

if [ "$status" -eq 2 ]; then
    exit 2
fi
if [ "$status" -eq 1 ] || [ "$errors" -ne 0 ]; then
    exit 1
fi
exit 0
