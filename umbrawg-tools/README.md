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
bench/bench.sh                  # матрица замеров (см. TODO.md)
```

## Документация для разработчика

Состояние проекта, известные проблемы и план работ — в [TODO.md](TODO.md).
