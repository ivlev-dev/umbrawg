# Вклад в umbrawg-tools

## Сборка

Нужен соседний репозиторий `netlink-packet-umbrawg` (path-зависимость `../netlink-packet-umbrawg`).

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
./scripts/check-packaging.sh
```

Минимальная поддерживаемая версия Rust — 1.85 (`rust-version` в манифесте).

## Стиль

- Комментарии в коде не добавляются.
- Строгая типизация, без `any`/неявных типов.
- Модульная архитектура: одна зона ответственности на модуль, зависимости направлены внутрь.
- Форматирование — `rustfmt` (конфигурация по умолчанию workspace).

## Коммиты и ветки

- Conventional Commits на русском: `feat(scope): описание`, `fix(...)`, `docs(...)`, `test(...)`, `refactor(...)`, `chore(...)`.
- Ветки: `feature/*`, `fix/*`, `docs/*`.
- Коммиты атомарные, один логический шаг.

## Тесты

- Тесты обязательны для нового кода: happy path, граничные случаи, ошибки.
- Запускать `cargo test --workspace` перед отправкой PR.
- Интеграционные сценарии: `scripts/test-userspace.sh`, `scripts/test-kernel.sh`, `scripts/test-two-nodes.sh`.

## Совместимость

- Не ломать wire-формат и UAPI-протокол без предупреждения.
- Обфускация 3.1 (`umbrawg-config`) должна оставаться совместимой с ядром и демоном.
- Изменения UAPI — только с обновлением обоих сторон (tools + daemon).
