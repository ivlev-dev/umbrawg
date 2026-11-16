# TODO — netlink-packet-umbrawg

## Текущее состояние

- Ветка `main`, всё слито и запушено.
- Крейт переименован: пакет `netlink-packet-umbrawg`, типы `Umbrawg*`, константы `UWG_*`.
- Полное покрытие AmneziaWG/UmbraWG 3.1, включая `RandomTrailers`, `DisableCookies`,
  `HeaderProtectionKey`, `ContentPaddingAddition`, `H1..H4`, `S1..S4`, `Jc/Jmin/Jmax`,
  `I1..I5`, rekey/keepalive-параметры.
- Тесты: 25 unit, 7 интеграционных против реального модуля `umbrawg`, 9 property-тестов
  (`proptest`), каркас фаззинга в `fuzz/`.
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

1. Документация: описания новых типов и примеров в rustdoc, `missing_docs` для публичного API.
2. Builder/conversions: удобные конструкторы устройства и пира с валидацией диапазонов.
3. Фаззинг: сборка целей в CI сделана; осталось починить найденные расхождения
   (`Peer`-атрибут round-trip, нормализация `H1Range..H4Range`).
4. Релиз 0.3.0 и решение о публикации в crates.io.
5. Синхронизировать README/CHANGELOG с текущим API.

## Соглашения

- Числовые значения атрибутов и байтовый layout менять нельзя.
- Коммиты на русском, Conventional Commits; ветки `feature/*`, слияние в `main`.
