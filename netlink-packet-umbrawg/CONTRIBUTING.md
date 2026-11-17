# Участие в разработке netlink-packet-umbrawg

## Сборка и тесты

```shell
cargo test
cargo clippy --all-targets -- -D warnings
cargo +nightly fmt --check
./scripts/check-uapi-parity.sh
```

## Стиль кода

- Без комментариев в коде.
- Строгая типизация Rust, без `any`/`unknown` без сужения (N/A для Rust — избегать `unwrap` в продакшен-коде, явные типы).
- Лицензия: MIT.
- Форматирование: `rustfmt` (nightly).

## Коммиты и ветки

- Conventional Commits на русском: `<type>(<scope>): <описание>`.
- Типы: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`, `ci`.
- Ветки: `feature/*`, слияние в `merge/ci-netlink` (или целевую).

## Сообщение об ошибке

Используйте шаблон `bug_report.yml`. Укажите версию крейта, версию genl (ядро), шаги, ожидаемое/фактическое, логи.

## Требования к PR

- `cargo test` и `cargo clippy` проходят.
- `check-uapi-parity.sh` проходит.
- Тесты для нового кода (happy path, граничные случаи, ошибки).
