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
- `.github/workflows/legacy-linux-build.yml` — прежняя C-сборка, только
  `workflow_dispatch`, без публикации релизов.

Оба workflow клонируют `ivlev-dev/netlink-packet-umbrawg` вторым checkout в
`netlink-packet-umbrawg/`, а сам репозиторий — в `tools/`. Поэтому
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
`umbrawg-tools` он ставится как готовый файл, сам демон поставляется отдельно.

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
scripts/test-two-nodes.sh       # 2 netns: ping + iperf3, с обфускацией и без
```

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
