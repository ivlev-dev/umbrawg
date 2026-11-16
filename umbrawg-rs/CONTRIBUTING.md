# Вклад в umbrawg-rs (UmbraWG userspace daemon)

## Сборка

```sh
cargo build --release -p umbrawg
cargo build --release --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Тесты с userspace-сетью (требуют `CAP_NET_ADMIN`/userns) запускаются отдельно
согласно CI (`ci.yml`, job `userns`). Параллельный приём включается
`UMBRAWG_PARALLEL_RX=1`.

Минимальная поддерживаемая версия Rust — 1.88 (`rust-version` в манифесте).
Только Linux (зависимости `libc`, `rustix`, `tokio`).

## Переменные окружения

`UMBRAWG_THREADS`, `UMBRAWG_PARALLEL_RX`, `UMBRAWG_RX_WORKERS`, `UMBRAWG_RX_SCHED`,
`UMBRAWG_RX_STATS`, `UMBRAWG_LOG_LEVEL`, `UMBRAWG_RUNTIME_DIR`. Подробнее — в README.

## Стиль

- Комментарии в коде не добавляются.
- Строгая типизация, без `any`/неявных типов.
- Модульная архитектура: одна зона ответственности на модуль, зависимости направлены внутрь.
- Форматирование — `rustfmt`.

## Коммиты и ветки

- Conventional Commits на русском: `feat(scope): описание`, `fix(...)`, `docs(...)`, `test(...)`, `refactor(...)`, `chore(...)`.
- Ветки: `feature/*`, `fix/*`, `docs/*`.
- Коммиты атомарные, один логический шаг.

## Тесты

- Тесты обязательны для нового кода: happy path, граничные случаи, ошибки.
- Запускать `cargo test --workspace` перед отправкой PR.
- Проверять оба режима: однопоточный и `UMBRAWG_PARALLEL_RX=1`.
- Проверять `UMBRAWG_RX_STATS=1` при изменениях приёма и оба режима
  `UMBRAWG_RX_SCHED=peer|queue` (data-plane: `scripts/test-dataplane-e2e.sh`,
  несколько пиров: `scripts/test-dataplane-multipeer.sh`).

## Совместимость

- Wire-совместимость с модулем ядра `umbrawg` (Noise IK, обфускация 3.1).
- UAPI-сокет `/var/run/umbrawg/<iface>.sock` — не менять протокол без обновления tools.
- Изменения transport/tun — проверять GSO/GRO и многопоточность.
