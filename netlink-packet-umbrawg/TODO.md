# TODO — netlink-packet-umbrawg

## Текущее состояние

- Ветка `main`, всё слито и запушено.
- Крейт `netlink-packet-umbrawg` 0.4.1 (2026-11-21): пакет
  `netlink-packet-umbrawg`, типы `Umbrawg*`, константы `UWG_*`.
- Полное покрытие AmneziaWG/UmbraWG 3.1, включая `RandomTrailers`, `DisableCookies`,
  `HeaderProtectionKey`, `ContentPaddingAddition`, `H1..H4`, `S1..S4`, `Jc/Jmin/Jmax`,
  `I1..I5`, rekey/keepalive-параметры, `ExtraPorts`, `UnderlayMtu`, `Bbr`,
  `Fec` (только `1..8 / 1..2`), `FecStats`, `BbrStats`.
- Паритет с `uapi/umbrawg.h`: `AdvancedSecurity`, `UWGPEER_F_HAS_ADVANCED_SECURITY`,
  `UWGALLOWEDIP_A_FLAGS`, `UWGALLOWEDIP_F_REMOVE_ME`, `UmbrawgCmd::UnknownPeer`.
- Тесты: 38 unit, 42 builder-теста (`tests/builders.rs`), 7 интеграционных против
  реального модуля `umbrawg`, 15 property-тестов (`proptest`), каркас фаззинга
  в `fuzz/`; форматирование — nightly `rustfmt`.
- `scripts/check-uapi-parity.sh` сверяет константы с заголовком ядра, включая
  `UWGDEVICE_A_FEC_STATS` (38), `BBR_STATS` (39) и `UNDERLAY_MTU` (40).
- Интеграционные тесты и примеры проверены на сервере с загруженным модулем.

## Сборка и тесты

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo run --example get_umbrawg_info -- uwg0
cargo run --example set_umbrawg -- uwg0
```

Интеграционные тесты требуют root и загруженного `umbrawg`; без них скипаются.

## Формат данных (важно для совместимости)

- `H1..H4` передаются как `u64` с упакованным диапазоном `u32` (`lo | hi << 32`).
- `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`,
  `KeepaliveTimeout`, `MaxHandshakeAttempts` — `u32` с упакованным `u16`-диапазоном
  (`lo | hi << 16`).
- `RandomTrailers`, `DisableCookies` — `u8`/`bool`.
- `HeaderProtectionKey` — ровно 32 байта.
- При заданном ключе header protection `S1..S4` должны быть ≥ длины nonce (4/12 в разных
  местах кода — сверяйтесь с `src/netlink.c` модуля).

## Что делать дальше (по приоритету)

1. ~~Документация: описания новых типов и примеров в rustdoc, `missing_docs`
   для публичного API.~~ Сделано: `#![deny(missing_docs)]`, описаны все
   публичные типы, варианты, поля и константы, добавлены примеры.
2. ~~Builder/conversions: удобные конструкторы устройства и пира с
   валидацией диапазонов.~~ Сделано: `UmbrawgDeviceConfig`,
   `UmbrawgPeerConfig`, `UmbrawgConfigError`, конверсии из сообщений и
   пиров, `UmbrawgAllowedIp::{new,remove,from_spec}`.
3. ~~Фаззинг: сборка целей в CI сделана; осталось починить найденные расхождения
   (`Peer`-атрибут round-trip исправлен в 0.3.0, `H1Range..H4Range` — проверить).~~
   Сделано: `cargo-fuzz` 0.13, `parse_message`/`parse_range` по 10 минут,
   исправлена паника на пустом `UWGALLOWEDIP_A_CIDR_MASK`; парсер магических
   заголовков сохраняет проводной формат (`H*`, `H*Range`, `H*Legacy`) и
   отклоняет перевёрнутые диапазоны.
4. Публикация 0.4.1 в crates.io (после проверки интеграции на сервере).
5. ~~Синхронизировать README с текущим API и CI.~~ Сделано: таблица атрибутов
   включает `ExtraPorts`/`UnderlayMtu`/`RandomTrailers`/`DisableCookies`/
   `FecStats`/`BbrStats`, теги и workflow называются `netlink-v*` и
   `netlink-packaging.yml`.

## Пакетирование и релиз

- `.github/workflows/netlink-packaging.yml`: `cargo test --all-targets`, сборка
  `contrib/arch/rust-netlink-packet-umbrawg-git` в `archlinux:latest` с проверкой
  содержимого `/usr/share/cargo/registry/netlink-packet-umbrawg-0.4.1` и офлайновой
  сборки потребителя через `[source] replace`, `cargo package`, `cargo publish --dry-run`;
  на тег `netlink-v*` в GitHub Release попадают `.pkg.tar.zst`, `.crate` и `SHA256SUMS`.
- Тег должен совпадать с версией из `Cargo.toml` (`netlink-v0.4.1`);
  иначе job `версия` падает до сборки.
- Секреты не нужны: crates.io и AUR не затрагиваются. Публикация крейта остаётся
  ручной (`cargo publish` с `CARGO_REGISTRY_TOKEN`), AUR — копированием
  `PKGBUILD`/`.SRCINFO` в AUR-репозиторий.
- Стабильный Arch-пакет `rust-netlink-packet-umbrawg` в CI не собирается: в
  `sha256sums` заглушка `TODO_UPDPKGSUMS_AFTER_FIRST_TAG`, после тега нужны
  `updpkgsums` и `makepkg --printsrcinfo > .SRCINFO`.
- Workflow проверен в Docker (`makepkg`, офлайновая сборка потребителя,
  `cargo package`, `cargo publish --dry-run`), но ни разу не прогонялся в
  GitHub Actions — первый прогон по тегу считать проверкой.

## Соглашения

- Числовые значения атрибутов и байтовый layout менять нельзя.
- Коммиты на русском, Conventional Commits; ветки `feature/*`, слияние в `main`.
