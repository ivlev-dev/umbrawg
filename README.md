# UmbraWG

[![Kernel build](https://github.com/ivlev-dev/umbrawg/actions/workflows/kernel-build.yml/badge.svg)](https://github.com/ivlev-dev/umbrawg/actions/workflows/kernel-build.yml)
[![netlink CI](https://github.com/ivlev-dev/umbrawg/actions/workflows/netlink-ci.yml/badge.svg)](https://github.com/ivlev-dev/umbrawg/actions/workflows/netlink-ci.yml)
[![tools CI](https://github.com/ivlev-dev/umbrawg/actions/workflows/tools-ci.yml/badge.svg)](https://github.com/ivlev-dev/umbrawg/actions/workflows/tools-ci.yml)
[![rs CI](https://github.com/ivlev-dev/umbrawg/actions/workflows/rs-ci.yml/badge.svg)](https://github.com/ivlev-dev/umbrawg/actions/workflows/rs-ci.yml)

Монорепозиторий UmbraWG — VPN-протокола на базе WireGuard с обфускацией трафика.
Версия 0.5.0 — 2026-11-23. В 0.5.0 BBR и ACK удалены: wire-расширение
состоит только из CAPS и FEC_SHARD, а FEC adaptive включён по умолчанию.

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
| `fec` | `adaptive` | `2:1` после потерь > 1%, off после < 0.2% в течение 5 с; `off` убирает extension-заголовки, fixed `K:M` включает parity сразу |
| `FEC_PARTIAL` | включён при `fec != off` | partial-блок с parity (`k' = n`, `m' = m`); у ядра отключается `fec_partial=0` |
| `underlay-mtu` | 1500 | MTU пути; при активном FEC из него выводятся MTU TUN и лимит шарда |

`uwg show <if> fec-stats` печатает счётчики FEC (блоки, шарды,
восстановления, decode-fail). В adaptive MTU не понижается, пока parity не
включился; fixed-профиль резервирует MTU сразу. Команды `bbr`/`bbr-stats`
возвращают ошибку «BBR удалён в 0.5.0».

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
  вручную через `workflow_dispatch`. Для 0.5.0 это
  `kernel-v0.5.0`, `netlink-v0.5.0`, `tools-v0.5.0`, `rs-v0.5.0` — каждый
  workflow реагирует только на свой префикс.

Подробности миграции и правила монорепо — [`docs/MONOREPO.md`](docs/MONOREPO.md).

## Документация

- Расширение протокола (CAPS/FEC_SHARD, флаги FEC, adaptive, бюджет MTU) —
  [`docs/PROTOCOL-EXT.md`](docs/PROTOCOL-EXT.md).
- Состояние FEC, замеры 0.5.0, `fec-stats` и ограничения —
  [`docs/FEC-STATUS.md`](docs/FEC-STATUS.md).
- Бенчмарк-матрица 2026-11-21 и полная матрица v4 2026-11-22 (четыре
  реализации, TCP/UDP, потери 0/2/5/10%, FEC, AES/mixed, обфускация,
  multi-peer 5/10/50, UDP-методика `-w 8M`, FEC RTT, slow-link). Деградация
  10 → 50 и single-flow закрыты work stealing (`c5457f06`/`0844f750`):
  8.25–9.12 Гбит/с, fairness 1.4–2.2, single-flow 3.08–3.14; AES на
  AES-NI/VAES быстрее ChaCha, classic RX — дефолт; parallel RX Rust на 50
  пирах разобран (OOM-киллер, пул уменьшен) —
  [`docs/BENCHMARKS-2026-11-21.md`](docs/BENCHMARKS-2026-11-21.md) (§14).
- Почему ядро отстаёт от Rust на одном пире и что это потребует —
  [`umbrawg-linux-kernel-module/docs/GAP-VS-RUST.md`](umbrawg-linux-kernel-module/docs/GAP-VS-RUST.md).
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
