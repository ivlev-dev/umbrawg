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
| `uwg` | CLI: `genkey`, `genpsk`, `pubkey`, `show`, `showconf`, `set`, `setconf` |
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

## Использование

```sh
uwg genkey | uwg pubkey
uwg show uwg0
uwg showconf uwg0
uwg setconf uwg0 /etc/umbrawg/uwg0.conf
uwg set uwg0 listen-port 51820
uwg-quick up uwg0
uwg-quick down uwg0
uwg-quick strip uwg0
```

Конфиги: `/etc/umbrawg/<iface>.conf`. Runtime: `/var/run/umbrawg/`.

Переменные окружения:

- `UWG_RUNTIME_DIR` — каталог UAPI-сокетов (по умолчанию `/var/run/umbrawg`);
- `UWG_QUICK_USERSPACE_IMPLEMENTATION` — демон для `uwg-quick up` (по умолчанию `umbrawg`);
- `UWG_COLOR_MODE`, `UWG_HIDE_KEYS` — оформление вывода.

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
