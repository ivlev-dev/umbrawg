# umbrawg-tools

Rust-утилиты для настройки UmbraWG: `uwg` и `uwg-quick`.

Работают с обоими бэкендами:

- модуль ядра `umbrawg` (generic netlink, семейство `umbrawg`);
- userspace-демон `umbrawg` (UAPI-сокет `/var/run/umbrawg/<iface>.sock`).

Бэкенд выбирается автоматически: если найден UAPI-сокет интерфейса — используется он,
иначе netlink.

## Состав

| Крейт | Назначение |
|---|---|
| `umbrawg-config` | ключи, конфигурация INI, параметры обфускации 3.1 |
| `umbrawg-ctl` | netlink- и UAPI-клиент, снимок состояния устройства |
| `uwg` | CLI: `genkey`, `genpsk`, `pubkey`, `show`, `showconf`, `set`, `setconf`, `addconf`, `syncconf`, `version`, `help` |
| `uwg-quick` | `up`, `down`, `strip`, `save` (порт `wg-quick` для Linux) |

`legacy-c/` — прежняя C-реализация (эталон поведения и тест-векторов), не собирается.
`contrib/` — сторонние примеры, не собираются.

## Сборка

Нужен соседний репозиторий `netlink-packet-umbrawg` (`Cargo.toml` использует path-зависимость
`../netlink-packet-umbrawg`).

```sh
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## CI

GitHub Actions:

- `.github/workflows/rust-ci.yml` — `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`;
- `.github/workflows/rust-build.yml` — release-сборка `uwg` и `uwg-quick` под
  `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` и
  `armv7-unknown-linux-gnueabihf`, релиз по тегу `v*`;
- `.github/workflows/packaging.yml` — пакеты `.deb`, `.rpm` и Arch в контейнерах
  на тег `v*`, публикация в GitHub Release (см. «Релизный CI пакетов»);
- `.github/workflows/legacy-linux-build.yml` — прежняя C-сборка, только
  `workflow_dispatch`, без публикации релизов.

Workflow с Rust-сборкой клонируют `ivlev-dev/netlink-packet-umbrawg` вторым
checkout в `netlink-packet-umbrawg/`, а сам репозиторий — в `tools/`. Поэтому
path-зависимость `../netlink-packet-umbrawg` разрешается без правки
`Cargo.toml`, локальная сборка не меняется.

Кроме fmt/clippy/test в `rust-ci.yml` есть:

- `bench` — `bash -n` стенда, тесты хелперов (62) и тесты отчёта (17);
- `packaging` — `scripts/check-packaging.sh`: версии `Cargo.toml` /
  `debian/changelog` / spec, `bash`/`sh`/`fish` синтаксис, YAML workflow,
  `groff -man -z`, `systemd-analyze verify` и проверка, что каждый
  поставляемый артефакт (man, completions, unit-файлы) реально ставится
  `debian/rules`, spec и `rust-build.yml`.

## Упаковка

Пакеты собираются из release-бинарников, без `make` и legacy-C:

```sh
scripts/package/make-dist.sh    # dist/umbrawg-tools-<version>.tar.gz (tools + netlink)
scripts/package/build-deb.sh    # dist/*.deb через dpkg-buildpackage -b
scripts/package/build-rpm.sh    # dist/*.rpm через rpmbuild -ba
```

Тарбол содержит оба каталога рядом, потому что Cargo-зависимость задана
относительным путём. `debian/` и `umbrawg-tools.spec` ставят:

- `uwg` и `uwg-quick`;
- `uwg(8)` и `uwg-quick(8)`;
- bash, zsh и fish completions;
- `uwg-quick@.service`, `uwg-quick.target`, `umbrawg@.service` для демона
  из `umbrawg-rs`;
- каталог `/etc/umbrawg` с правами `0700`.

Юнит `umbrawg@.service` рассчитан на демон `umbrawg` из `umbrawg-rs`; в пакет
`umbrawg-tools` он ставится как готовый файл, сам демон поставляется отдельно,
поэтому до установки `umbrawg` `systemd-analyze verify` ругается на
отсутствующий `ExecStart`.

### Сборка в Docker

Оба дерева (`umbrawg-tools` и `netlink-packet-umbrawg`) должны лежать рядом;
каталог репозитория монтируется в контейнер, `-w` указывает на `umbrawg-tools`.

`.deb` собирается на дистрибутиве с `cargo`/`rustc` >= 1.85 из архива, тогда
`dpkg-buildpackage` проверяет `Build-Depends` как обычно:

```sh
docker run --rm -v "$(cd .. && pwd):/src" -w "/src/$(basename "$PWD")" \
  debian:trixie bash -c 'apt-get update && apt-get install -y --no-install-recommends \
    build-essential cargo rustc dpkg-dev debhelper ca-certificates && \
    scripts/package/build-deb.sh'
```

В образах с rustup (`rust:1.85-bookworm`) пакетов `cargo`/`rustc` нет, и
`dpkg-checkbuilddeps` не может их подтвердить. В этом случае `build-deb.sh`
проверяет `cargo`, `rustc`, `dh` в `PATH`, сверяет версию `rustc` с
`rust-version` из `Cargo.toml` и только затем передаёт `dpkg-buildpackage -d`.

`.rpm` собирается в Fedora:

```sh
docker run --rm -v "$(cd .. && pwd):/src" -w "/src/$(basename "$PWD")" \
  fedora:latest bash -c 'dnf install -y rpm-build cargo rust gcc make \
    systemd-rpm-macros && scripts/package/build-rpm.sh'
```

Готовые файлы складываются в `dist/`. Проверка содержимого:

```sh
dpkg-deb -c dist/umbrawg-tools_*.deb
dpkg-deb -I dist/umbrawg-tools_*.deb
rpm -qlp dist/umbrawg-tools-*.x86_64.rpm
rpm -qip dist/umbrawg-tools-*.x86_64.rpm
lintian dist/umbrawg-tools_*.deb
```

Юниты в `.deb` ставятся в `/lib/systemd/system`: так их находит debhelper 13
из bookworm и генерирует maint-скрипты; на merged-/usr это тот же
`/usr/lib/systemd/system`. Преднамеренные отклонения (`/lib`, режим `0700` у
`/etc/umbrawg`) описаны в `debian/umbrawg-tools.lintian-overrides`.

### Релизный CI пакетов

`.github/workflows/packaging.yml` повторяет проверенные рецепты выше на
раннерах GitHub Actions:

| Job | Образ | Шаги |
|---|---|---|
| `meta` | `ubuntu-latest` | версия из `Cargo.toml`, сверка с тегом `v*` или с input `version` |
| `deb` | `debian:trixie` | `build-essential cargo rustc dpkg-dev debhelper`, затем `scripts/package/build-deb.sh` |
| `rpm` | `fedora:latest` | `rpm-build cargo rust gcc make systemd-rpm-macros`, затем `scripts/package/build-rpm.sh` |
| `arch` | `archlinux:latest` | `base-devel git rust cargo`, затем `makepkg -f --noconfirm --nodeps` |
| `release` | `ubuntu-latest` | `SHA256SUMS` и `softprops/action-gh-release` |

Триггеры:

- push тега `v*` — сборка и публикация в GitHub Release;
- `workflow_dispatch` — только артефакты, без релиза; необязательный input
  `version` (без префикса `v`) сверяется с `Cargo.toml`:

  ```sh
  gh workflow run packaging.yml -f version=0.2.0
  ```

Каждый build-job выкладывает артефакт со сроком хранения 14 дней:
`umbrawg-tools-deb` (`dist/*.deb`, `*.changes`, `*.buildinfo`),
`umbrawg-tools-rpm` и `umbrawg-tools-arch` (`*.pkg.tar.zst`). В rpm-артефакт
попадают SRPM и `-debuginfo`/`-debugsource`, в arch — `-debug`: это обычный
вывод `rpmbuild` и `makepkg`, они же уходят в релиз. Job `release` скачивает
все три артефакта, считает `SHA256SUMS` и прикладывает их к релизу того же
тега, куда `rust-build.yml` кладёт тарболы бинарников; оба релизных job'а
используют общую concurrency-группу `release-${{ github.ref }}`, поэтому не
перезаписывают релиз одновременно.

Особенности:

- `deb` и `rpm` чекаутят оба дерева (`tools/` и `netlink-packet-umbrawg/`) —
  этого требует `make-dist.sh`. В `debian:trixie` `rustc` уже >= 1.85, так что
  `dpkg-checkbuilddeps` подтверждает `Build-Depends` и `-d` не нужен;
  на `rust:1.85-bookworm` скрипт, как и локально, сверит версию и добавит `-d`.
- Версия netlink в default-ветке должна совпадать с `Cargo.lock`. Иначе
  `.deb`/`.rpm` соберутся, но cargo перепишет lock; а Arch `-git` упадёт на
  `cargo fetch --locked`. Перед тегом tools приведите `main` netlink к версии
  из lock или обновите `Cargo.lock`.
- Arch `-git` PKGBUILD тянет исходники сам: `master` tools и `main` netlink из
  GitHub, локальный checkout для него не используется. Пакет поэтому
  VCS-снимок (`pkgver` вида `0.2.0.r<N>.g<хэш>`), а job дополнительно проверяет,
  что версия в имени файла начинается с версии из `Cargo.toml`: тег должен
  указывать на HEAD той ветки, которую клонирует PKGBUILD.
- Стабильный Arch-пакет собирается только если в
  `contrib/arch/umbrawg-tools/PKGBUILD` нет заглушки
  `TODO_UPDPKGSUMS_AFTER_FIRST_TAG`. До первого тега netlink и `updpkgsums`
  job печатает `skip` и кладёт в артефакт только `-git`. Источники стабильного
  пакета — архивы тегов из его `PKGBUILD` (`pkgver`, `_netlink_ver`), поэтому
  перед тегом версии и суммы обновляют вручную; при рассинхроне `makepkg`
  упадёт на проверке контрольных сумм.
- `scripts/check-packaging.sh` (job `packaging` в `rust-ci.yml`) разбирает все
  YAML workflow, поэтому синтаксические ошибки в `packaging.yml` видны до тега;
  локальные рецепты — раздел «Сборка в Docker».

Секреты и права:

- отдельных секретов не нужно, достаточно автоматического `GITHUB_TOKEN`;
- на уровне workflow `permissions: contents: read`, у job `release` —
  `contents: write` (создание релиза и загрузка файлов);
- оба репозитория должны оставаться публичными: `actions/checkout` второго
  дерева и `makepkg` клонируют `ivlev-dev/netlink-packet-umbrawg` без токена;
- публикация в AUR не автоматизирована — нужен отдельный AUR-репозиторий и
  SSH-ключ (см. `contrib/arch/README.md`).

## Использование

```sh
uwg genkey | uwg pubkey
uwg version
uwg help
uwg show uwg0
uwg show uwg0 advanced-security
uwg showconf uwg0
uwg setconf uwg0 /etc/umbrawg/uwg0.conf
uwg addconf uwg0 /etc/umbrawg/uwg0.conf
uwg syncconf uwg0 <(uwg-quick strip uwg0)
uwg set uwg0 listen-port 51820
uwg-quick up uwg0
uwg-quick down uwg0
uwg-quick strip uwg0
```

Конфиги: `/etc/umbrawg/<iface>.conf`. Runtime: `/var/run/umbrawg/`.

Переменные окружения:

- `UWG_RUNTIME_DIR` — каталог UAPI-сокетов (по умолчанию `/var/run/umbrawg`);
- `UWG_QUICK_USERSPACE_IMPLEMENTATION` — демон для `uwg-quick up` (по умолчанию `umbrawg`);
- `WG_COLOR_MODE` (`always`/`never`), `WG_HIDE_KEYS` — оформление вывода.

## Параметры обфускации

Поддерживаются все параметры UmbraWG 3.1: `H1..H4`, `S1..S4`, `Jc`, `Jmin`, `Jmax`,
`I1..I5`, `HeaderProtectionKey`, `ContentPaddingAddition`, `RandomTrailers`, `DisableCookies`,
`RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`.

Пример профиля — `bench/obf-params.conf`.

## Тесты и стенд

```sh
cargo test --workspace          # unit + CLI + parity strip против legacy-c
scripts/test-kernel.sh          # утилиты против модуля ядра
scripts/test-userspace.sh       # утилиты против userspace-демона
scripts/test-daemon-e2e.sh      # e2e: uwg ↔ живой umbrawg через UAPI (без модуля ядра)
scripts/test-two-nodes.sh       # 2 netns: ping + iperf3, с обфускацией и без
```

`scripts/test-daemon-e2e.sh` поднимает Rust-демон `umbrawg --foreground` в
отдельном namespace (`unshare -Urn`, если нет root/CAP_NET_ADMIN) с
`UWG_RUNTIME_DIR` во временном каталоге и прогоняет через UAPI полный профиль
3.1 (`H1..H4`, `S1..S4`, `Jc/Jmin/Jmax`, `I1..I5`, `HeaderProtectionKey`,
`AdvancedSecurity`), `show`/`showconf`, `set`, `addconf`, `syncconf`,
перезапуск демона и отрицательные сценарии. Каждая команда проверяется по коду
возврата и пустому stderr (предупреждения считаются ошибкой), `showconf`
сравнивается с исходным конфигом после нормализации. Скрипт завершается с
кодом 0 и сообщением `SKIP`, если нет бинарников, TUN или прав на namespace.
Пути задаются через `UWG` и `DAEMON`; при их отсутствии берутся
`target/release/uwg` и `../rust/target/release/umbrawg`. `KEEP_ARTIFACTS=1`
сохраняет каталог прогона.

### Стенд замеров (bench/)

`bench/` — изолированный стенд: два netns (`bn0`/`bn1`), veth-пара, iperf3,
матрица реализаций/режимов/протоколов, MTU-guard, CPU-профиль и отчёт в
Markdown. Подробности и методика — [bench/README.md](bench/README.md).

```sh
SMOKE=1 bash bench/bench.sh                        # быстрый прогон (нужен root)
PLAN_ONLY=1 FORCE=1 bash bench/bench.sh             # план без трафика, без root
bash bench/tests/test-bench-lib.sh                  # 62 проверки хелперов
python3 -m unittest discover -s bench/tests -p 'test_*.py'   # 17 тестов отчёта
scripts/check-packaging.sh                          # man/systemd/completions/версии
```

Пути не зашиты в скрипт: `BENCH_DIR` — каталог `bench.sh`, `REPO_ROOT` — этот
репозиторий (бинарник `target/release/uwg`), `WORKSPACE_ROOT` — каталог
соседних репозиториев. Переопределяются `RUSTDIR`, `MODDIR` (он же
`MODULE_DIR`), `UWG`, `DAEMON`, `GO_BASELINE`, `OBF`, `RESULT`, `REPORT_PY`.
Если стенд развёрнут отдельно (например, `/root/umbrawg/bench`), достаточно
задать эти переменные — см. таблицу в [bench/README.md](bench/README.md).

Матрица: `IMPL_LIST`, `MODE_LIST`, `PROTO_LIST`, `CONNS_LIST`, `LOSS_LIST`,
`OBF_LIST`, `PEERS_LIST`, `DURATION`, `SMOKE`, `REPEATS`, `UDP_RATE`,
`UDP_RATE_LIST`, `UNDERLAY_MTU`, `TUN_MTU`, `PLAN_ONLY`, `FORCE`, `RESULT`,
`RUN_ID`, `CPU_HOT_PCT`. Перед прогоном проверяется наличие нужных бинарников
(`REQUIRE_FAILED`, код 5), MTU-guard (`TUN_MTU` против `UNDERLAY_MTU`) и
занятость машины (`IDLE_GUARD`, код 3).

## Документация для разработчика

Состояние проекта, известные проблемы и план работ — в [TODO.md](TODO.md).
