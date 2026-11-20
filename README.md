# UmbraWG

[![Kernel build](https://github.com/ivlev-dev/umbrawg/actions/workflows/kernel-build.yml/badge.svg)](https://github.com/ivlev-dev/umbrawg/actions/workflows/kernel-build.yml)
[![netlink CI](https://github.com/ivlev-dev/umbrawg/actions/workflows/netlink-ci.yml/badge.svg)](https://github.com/ivlev-dev/umbrawg/actions/workflows/netlink-ci.yml)
[![tools CI](https://github.com/ivlev-dev/umbrawg/actions/workflows/tools-ci.yml/badge.svg)](https://github.com/ivlev-dev/umbrawg/actions/workflows/tools-ci.yml)
[![rs CI](https://github.com/ivlev-dev/umbrawg/actions/workflows/rs-ci.yml/badge.svg)](https://github.com/ivlev-dev/umbrawg/actions/workflows/rs-ci.yml)
[![Go](https://github.com/ivlev-dev/umbrawg/actions/workflows/go-ci.yml/badge.svg)](https://github.com/ivlev-dev/umbrawg/actions/workflows/go-ci.yml)

Монорепозиторий UmbraWG — VPN-протокола на базе WireGuard с обфускацией трафика.

## Что внутри

| Каталог | Что это | Стек |
|---|---|---|
| `umbrawg-linux-kernel-module/` | модуль ядра Linux (`umbrawg.ko`), DKMS, пакеты Arch/RPM/DEB | C, Kbuild |
| `netlink-packet-umbrawg/` | крейт разбора generic netlink UAPI | Rust |
| `umbrawg-tools/` | CLI `uwg`, `uwg-quick`, конфиг и netlink-клиент | Rust |
| `umbrawg-rs/` | userspace-демон (альтернатива модулю ядра) | Rust |
| `go/` | Go-реализация (форк wireguard-go) | Go |
| `bench/` | стенд: сценарии замеров, анализ, конфиги | Bash/Python |
| `docs/` | общая документация монорепозитория | Markdown |

Компоненты сохраняют собственные `README`, `docs/`, `CHANGELOG` и системы
сборки; общими являются только корневые правила и CI.

## Сборка и проверка

```sh
# модуль ядра
cd umbrawg-linux-kernel-module/src && make LLVM=1 -j"$(nproc)"

# netlink-крейт
cd netlink-packet-umbrawg && cargo test && cargo clippy --all-targets

# CLI
cd umbrawg-tools && cargo test --workspace && cargo clippy --workspace --all-targets

# userspace-демон
cd umbrawg-rs && cargo test --workspace && cargo clippy --workspace --all-targets

# Go-реализация
cd go && go build ./... && go test ./...
```

Требования: Linux ≥ 7.0 и clang/LLVM для модуля, Rust 1.85
(`umbrawg-tools`, `netlink-packet-umbrawg`) и 1.88 (`umbrawg-rs`), Go 1.25.

## Ветки и релизы

- Основная ветка — `master`. Работа идёт в feature-ветках, после проверки
  вливается в `master` и ветка удаляется.
- Теги версий — с префиксом компонента:

  | Компонент | Формат тега | Версия берётся из |
  |---|---|---|
  | модуль ядра | `kernel-vX.Y.Z` | `umbrawg-linux-kernel-module/src/version.h` |
  | netlink | `netlink-vX.Y.Z` | `netlink-packet-umbrawg/Cargo.toml` |
  | CLI | `tools-vX.Y.Z` | `umbrawg-tools/Cargo.toml` |
  | userspace | `rs-vX.Y.Z` | `umbrawg-rs/Cargo.toml` |

- CI запускается по `paths`-фильтрам: изменения в `bench/` или `docs/` не
  пересобирают модуль.
- Упаковка (Arch, RPM, DEB, DKMS, `.crate`) запускается тегом компонента или
  вручную через `workflow_dispatch`.

Подробности миграции и правила монорепо — [`docs/MONOREPO.md`](docs/MONOREPO.md).

## Документация

- Расширение протокола (CAPS/ACK/FEC_SHARD, BBRv3, бюджет MTU) —
  [`docs/PROTOCOL-EXT.md`](docs/PROTOCOL-EXT.md).
- Состояние BBRv3/FEC, финальные замеры и ограничения —
  [`docs/BBR-FEC-STATUS.md`](docs/BBR-FEC-STATUS.md).
- Производительность и отклонённые эксперименты —
  `umbrawg-linux-kernel-module/docs/PERFORMANCE.md`.
- Дизайн шардирования — `umbrawg-linux-kernel-module/docs/PEER-SHARDING.md`
  (S1/S2) и `umbrawg-linux-kernel-module/docs/PEER-PATH-SHARDING.md` (S3).
- Стенд и методика — `bench/README.md`; результаты замеров хранятся на
  тестовом сервере, а не в репозитории.

## Лицензии

Компоненты лицензированы по отдельности: модуль ядра — GPL-2.0,
`umbrawg-tools` — GPL-2.0-only, `umbrawg-rs` и `netlink-packet-umbrawg` — MIT,
`go/` — MIT. См. `LICENSE`/`COPYING` в каталогах компонентов.
