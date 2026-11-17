#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tools_dir="$(cd "$script_dir/.." && pwd)"
cd "$tools_dir"

failures=0

bad() {
    printf 'FAIL: %s\n' "$*" >&2
    failures=$((failures + 1))
}

ok_if_clean() {
    local before=$1 msg=$2
    if [ "$failures" = "$before" ]; then
        printf 'ok: %s\n' "$msg"
    fi
}

skip() {
    printf 'skip: %s\n' "$*"
}

require_file() {
    local f
    for f in "$@"; do
        if [ ! -e "$f" ]; then
            bad "нет файла: $f"
        fi
    done
}

check_versions() {
    local ws deb rpm before=$failures
    ws="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
    deb="$(sed -n '1s/.*(\(.*\)).*/\1/p' debian/changelog)"
    rpm="$(sed -n 's/^Version:[[:space:]]*\([^[:space:]]*\).*/\1/p' umbrawg-tools.spec | head -n1)"
    if [ -z "$ws" ]; then
        bad "не найдена версия workspace в Cargo.toml"
        return 0
    fi
    if [ "$ws" != "$deb" ]; then
        bad "debian/changelog=$deb, Cargo.toml=$ws"
    fi
    if [ "$ws" != "$rpm" ]; then
        bad "umbrawg-tools.spec=$rpm, Cargo.toml=$ws"
    fi
    ok_if_clean "$before" "версии: $ws"
}

check_scripts() {
    local f before=$failures
    while IFS= read -r f; do
        bash -n "$f" || bad "bash -n $f"
    done < <(find scripts bench completions -type f \( -name '*.sh' -o -name '*.bash' \) | sort)
    sh -n debian/tests/smoke || bad "sh -n debian/tests/smoke"
    if command -v fish >/dev/null 2>&1; then
        while IFS= read -r f; do
            fish --no-execute "$f" || bad "fish --no-execute $f"
        done < <(find completions -type f -name '*.fish' | sort)
        ok_if_clean "$before" "bash/sh/fish синтаксис"
    else
        skip "fish не установлен"
        ok_if_clean "$before" "bash/sh синтаксис"
    fi
}

check_yaml() {
    local before=$failures
    if ! python3 -c 'import yaml' >/dev/null 2>&1; then
        skip "PyYAML не установлен"
        return 0
    fi
    python3 - <<'PY' || bad "YAML workflow не разбирается"
import pathlib

import yaml

for path in sorted(pathlib.Path("../.github/workflows").glob("*.yml")):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not data.get("jobs"):
        raise SystemExit(f"{path}: нет секции jobs")
    for name, job in data["jobs"].items():
        if "runs-on" not in job:
            raise SystemExit(f"{path}: job {name} без runs-on")
PY
    ok_if_clean "$before" "YAML workflow"
}

check_debian_meta() {
    local before=$failures
    if ! python3 -c 'import debian.deb822' >/dev/null 2>&1; then
        skip "python3-debian не установлен"
        return 0
    fi
    python3 - <<'PY' || bad "метаданные debian/"
import contextlib
import io
import pathlib

from debian.changelog import Changelog
from debian.deb822 import Deb822, PkgRelation

paragraphs = list(Deb822.iter_paragraphs(pathlib.Path("debian/control").read_text(encoding="utf-8")))
source = paragraphs[0]["Source"]
changelog = Changelog(pathlib.Path("debian/changelog").read_text(encoding="utf-8"))
if changelog.package != source:
    raise SystemExit(f"debian/changelog: {changelog.package} != debian/control Source: {source}")

errors: list[str] = []
for paragraph in paragraphs:
    name = paragraph.get("Source") or paragraph.get("Package") or "?"
    for field in ("Build-Depends", "Depends", "Recommends", "Suggests", "Build-Depends-Indep"):
        value = paragraph.get(field)
        if not value:
            continue
        with contextlib.redirect_stderr(io.StringIO()):
            groups = PkgRelation.parse_relations(value)
        for group in groups:
            if isinstance(group, str):
                if not group.strip().startswith("${"):
                    errors.append(f"{name}: {field}: не разбирается {group!r}")
                continue
            for relation in group:
                if not relation.get("name"):
                    errors.append(f"{name}: {field}: пустое отношение (лишняя запятая?)")
if errors:
    raise SystemExit("\n".join(errors))
PY
    ok_if_clean "$before" "debian/control и changelog"
}

check_man() {
    local f out before=$failures
    if ! command -v groff >/dev/null 2>&1; then
        skip "groff не установлен"
        return 0
    fi
    for f in man/*.8; do
        if ! out="$(groff -man -z -ww "$f" 2>&1)"; then
            bad "groff $f: $out"
        fi
    done
    ok_if_clean "$before" "man-страницы"
}

check_units() {
    local out filtered before=$failures
    if ! command -v systemd-analyze >/dev/null 2>&1; then
        skip "systemd-analyze не установлен"
        return 0
    fi
    out="$(systemd-analyze verify --man=no systemd/*.service systemd/*.target 2>&1 || true)"
    filtered="$(printf '%s\n' "$out" | grep -v 'is not executable' | grep -v '^$' |
        grep -vE '^(/usr)?/lib/systemd/system/' || true)"
    if [ -n "$filtered" ]; then
        bad "systemd-analyze verify: $filtered"
    fi
    ok_if_clean "$before" "systemd-юниты"
}

check_artifacts() {
    local f src before=$failures
    require_file \
        man/uwg.8 man/uwg-quick.8 \
        completions/uwg.bash completions/uwg-quick.bash \
        completions/_uwg completions/_uwg-quick \
        completions/uwg.fish completions/uwg-quick.fish \
        systemd/uwg-quick@.service systemd/uwg-quick.target systemd/umbrawg@.service \
        README.md CHANGELOG.md COPYING \
        debian/rules debian/control debian/changelog debian/tests/smoke \
        umbrawg-tools.spec \
        bench/bench.sh bench/bench-lib.sh bench/bench-report.py bench/obf-params.conf

    for f in man/*.8 completions/* systemd/*; do
        grep -q -- "$f" debian/rules || bad "debian/rules не ставит $f"
        grep -q -- "$f" umbrawg-tools.spec || bad "umbrawg-tools.spec не ставит $f"
        grep -q -- "$f" ../.github/workflows/tools-ci.yml || bad "tools-ci.yml не ставит $f"
    done

    while IFS= read -r src; do
        case "$src" in
            ""|*'$'*|*%*|target/*) continue ;;
        esac
        if [ ! -e "$src" ]; then
            bad "упаковка ссылается на отсутствующий файл: $src"
        fi
    done < <(
        {
            grep -hE '^[[:space:]]*install -Dm[0-7]+ ' ../.github/workflows/tools-ci.yml ../.github/workflows/tools-packaging.yml debian/rules 2>/dev/null |
                awk '{ print $3 }' | tr -d '"'
            grep -hE '^[[:space:]]*install -Dpm[0-7]+ ' umbrawg-tools.spec |
                awk '{ print $3 }' | sed 's|^target/.*||'
        } | sort -u
    )
    ok_if_clean "$before" "артефакты упаковки"
}

check_versions
check_scripts
check_yaml
check_debian_meta
check_man
check_units
check_artifacts

if [ "$failures" != "0" ]; then
    printf 'PACKAGING: FAIL\n' >&2
    exit 1
fi
printf 'PACKAGING: OK\n'
