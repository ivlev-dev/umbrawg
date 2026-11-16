# Участие в разработке UmbraWG (kernel module)

Спасибо за интерес к проекту. Ниже — краткие правила.

## Сборка

```shell
cd src
make LLVM=1          # clang-сборка (обязательна для ядер, собранных clang, например Arch/CachyOS)
make module-debug    # сборка с отладкой (CONFIG_UMBRAWG_DEBUG=y)
```

На ядрах, собранных gcc, `LLVM=1` не обязателен, но рекомендуется для единообразия.

## Тестирование

- Запуск parity-проверок netlink-интерфейса: `src/tests/netlink-parity.sh` (требует загруженный модуль и права root).
- Стиль кода: `make style` (checkpatch).
- Статический анализ: `make check` (scan-build).

## Стиль кода

- Без комментариев в коде.
- Лицензия: GPLv2 (см. `COPYING`).
- Следуйте существующему стилю ядра Linux (checkpatch).

## Коммиты и ветки

- Conventional Commits на русском: `<type>(<scope>): <описание>`.
- Типы: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`, `ci`.
- Ветки: `feature/*`, слияние в `master`.
- Один логический change — один коммит.

## Сообщение об ошибке

Используйте шаблон `bug_report.yml` (Issues → New issue). Укажите версию/коммит, ядро (`uname -r`), вывод `modinfo umbrawg`, шаги воспроизведения, ожидаемое/фактическое поведение и логи (`dmesg`).

## Требования к PR

- Тесты/проверки проходят.
- Нет регрессий в netlink-parity.
- Не ломайте обратную совместимость wire-формата и числовых констант UAPI.
