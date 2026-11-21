# UmbraWG

[![Kernel build](https://github.com/ivlev-dev/umbrawg/actions/workflows/kernel-build.yml/badge.svg)](https://github.com/ivlev-dev/umbrawg/actions/workflows/kernel-build.yml)
[![netlink CI](https://github.com/ivlev-dev/umbrawg/actions/workflows/netlink-ci.yml/badge.svg)](https://github.com/ivlev-dev/umbrawg/actions/workflows/netlink-ci.yml)
[![tools CI](https://github.com/ivlev-dev/umbrawg/actions/workflows/tools-ci.yml/badge.svg)](https://github.com/ivlev-dev/umbrawg/actions/workflows/tools-ci.yml)
[![rs CI](https://github.com/ivlev-dev/umbrawg/actions/workflows/rs-ci.yml/badge.svg)](https://github.com/ivlev-dev/umbrawg/actions/workflows/rs-ci.yml)

Монорепозиторий UmbraWG — VPN-протокола на базе WireGuard с обфускацией трафика.
Версия 0.4.1 — 2026-11-21.

## Что внутри

| Каталог | Что это | Стек |
|---|---|---|
| `umbrawg-linux-kernel-module/` | модуль ядра Linux (`umbrawg.ko`), DKMS, пакеты Arch/RPM/DEB | C, Kbuild |
| `netlink-packet-umbrawg/` | крейт разбора generic netlink UAPI | Rust |
| `umbrawg-tools/` | CLI `uwg`, `uwg-quick`, конфиг и netlink-клиент | Rust |
| `umbrawg-rs/` | userspace-демон (альтернатива модулю ядра) | Rust |
| `bench/` | стенд: сценарии замеров, анализ, конфиги | Bash/Python |
| `docs/` | общая документация монорепозитория | Markdown |

Компоненты сохраняют собственные `README`, `docs/`, `CHANGELOG` и системы
сборки; общими являются только корневые правила и CI.

### Значения по умолчанию (userspace-демон)

| Параметр | Значение | Комментарий |
|---|---|---|
| `UMBRAWG_SOCKET_BUFFER` | 8 МиБ (`8388608`) | было 4 МиБ в 0.3.0; меньше — только если ядро урезает `rmem_max`/`wmem_max` |
| `UMBRAWG_GSO_SEGMENTS` | 64 | было 32 в 0.3.0; диапазон 1..64 |
| `ExtraPorts` | 0 | дополнительные UDP-порты выключены; на стенде включали 4 |
| `bbr` / `fec` | `off` / `off` | при обоих `off` extension-заголовков нет |
| `FEC_PARTIAL` | включён при `fec != off` | partial-блок с parity (`k' = n`, `m' = m`); у ядра отключается `fec_partial=0` |
| `underlay-mtu` | 1500 | MTU пути; при FEC из него выводятся MTU TUN и лимит шарда |

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
```

Требования: Linux ≥ 7.0 и clang/LLVM для модуля, Rust 1.85
(`umbrawg-tools`, `netlink-packet-umbrawg`) и 1.88 (`umbrawg-rs`).

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
  вручную через `workflow_dispatch`. Для 0.4.1 это
  `kernel-v0.4.1`, `netlink-v0.4.1`, `tools-v0.4.1`, `rs-v0.4.1` — каждый
  workflow реагирует только на свой префикс.

Подробности миграции и правила монорепо — [`docs/MONOREPO.md`](docs/MONOREPO.md).

## Документация

- Расширение протокола (CAPS/ACK/FEC_SHARD, BBRv3, бюджет MTU) —
  [`docs/PROTOCOL-EXT.md`](docs/PROTOCOL-EXT.md).
- Состояние BBRv3/FEC, финальные замеры и ограничения —
  [`docs/BBR-FEC-STATUS.md`](docs/BBR-FEC-STATUS.md).
- Бенчмарк-матрица 2026-11-21: baseline AmneziaWG, потери 0/2/5/10%, FEC/BBR,
  AES/mixed, обфускация, multi-peer 5/10/50, UDP-методика (`-w 8M`),
  FEC RTT, slow-link —
  [`docs/BENCHMARKS-2026-11-21.md`](docs/BENCHMARKS-2026-11-21.md).
- Производительность и отклонённые эксперименты —
  [`umbrawg-linux-kernel-module/docs/PERFORMANCE.md`](umbrawg-linux-kernel-module/docs/PERFORMANCE.md).
- Полная матрица TCP/UDP, data-plane e2e и сравнение реализаций —
  [`umbrawg-tools/docs/RESULTS.md`](umbrawg-tools/docs/RESULTS.md).
- Дизайн шардирования — [`umbrawg-linux-kernel-module/docs/PEER-SHARDING.md`](umbrawg-linux-kernel-module/docs/PEER-SHARDING.md)
  (S1/S2) и [`umbrawg-linux-kernel-module/docs/PEER-PATH-SHARDING.md`](umbrawg-linux-kernel-module/docs/PEER-PATH-SHARDING.md) (S3).
- Стенд и методика — [`bench/README.md`](bench/README.md). Сырые CSV и
  pcap-дампы остаются на тестовом сервере; в репозитории — скрипты, конфиги
  и небольшие эталонные CSV (`umbrawg-tools/bench/baselines/`).

## Лицензии

Компоненты лицензированы по отдельности: модуль ядра — GPL-2.0,
`umbrawg-tools` — GPL-2.0-only, `umbrawg-rs` и `netlink-packet-umbrawg` — MIT.
См. `LICENSE`/`COPYING` в каталогах компонентов.
