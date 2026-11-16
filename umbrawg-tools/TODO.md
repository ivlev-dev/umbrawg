# TODO — umbrawg-tools

## Текущее состояние

- Ветка `master` (после слияния `feature/rust-tools`), всё запушено.
- C-реализация сохранена в `legacy-c/` как поведенческий эталон и источник тест-векторов.
- Rust-утилиты: `uwg` (genkey, genpsk, pubkey, show, showconf, set, setconf,
  addconf, syncconf, version, help) и `uwg-quick` (up, down, strip, save).
- Транспорт управления: kernel netlink (семейство `umbrawg`) и userspace UAPI
  (`/var/run/umbrawg/<iface>.sock`) с автовыбором.
- Конфигурация: INI с полным набором параметров AmneziaWG/UmbraWG 3.1;
  парсинг `uwg-quick` переведён на общие примитивы `umbrawg-config`.
- AdvancedSecurity пира: чтение флага из netlink (`uwg show`,
  `uwg show <iface> advanced-security`); ядро выставляет его само.
- Тесты: 190 (unit, 10 CLI на фейковом UAPI-сокете, 2 parity-теста `strip`
  против bash-версии).
- CI: fmt/clippy/test, тесты стенда (`bench`) и статические проверки упаковки
  (`packaging`), релизные сборки x86_64/aarch64/armv7; упаковка
  deb/rpm/man/completions/systemd из Rust-дерева; на тег `v*` —
  `.github/workflows/packaging.yml` собирает `.deb`, `.rpm` и Arch `-git` и
  публикует их в релиз вместе с `SHA256SUMS`.
- Интеграционные скрипты: `scripts/test-kernel.sh`, `scripts/test-userspace.sh`,
  `scripts/test-two-nodes.sh` — проходят на сервере.
- Стенд замеров: `bench/bench.sh` (матрица, повторы, MTU-guard, CPU-профиль),
  `bench/bench-report.py` (Markdown + агрегат), тесты стенда в `bench/tests/`,
  `bench/verify*.sh` (проверки userspace↔userspace и userspace↔ядро),
  `bench/obf-params.conf`. Пути к соседним репозиториям не зашиты: см.
  `bench/README.md`.
- Статические проверки упаковки: `scripts/check-packaging.sh` (версии,
  man-страницы, systemd-юниты, completions, YAML, артефакты в правилах
  сборки), job `packaging` в CI.

## Сборка и тесты

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release
```

Бинари: `target/release/uwg`, `target/release/uwg-quick`.

Для сборки нужен репозиторий `netlink-packet-umbrawg` рядом (`../netlink-packet-umbrawg`
в `Cargo.toml`).

## Использование

```sh
uwg genkey | uwg pubkey
uwg show uwg0
uwg setconf uwg0 /etc/umbrawg/uwg0.conf
uwg-quick up uwg0
uwg-quick strip uwg0 > /tmp/config
```

Конфиги: `/etc/umbrawg/<iface>.conf`; runtime: `/var/run/umbrawg/`.
Переменные окружения: `UWG_QUICK_USERSPACE_IMPLEMENTATION`, `UWG_COLOR_MODE`, `UWG_HIDE_KEYS`,
`UWG_RUNTIME_DIR`.

## Стенд (bench/)

```sh
bench/bench.sh                 # матрица: impl × mode × proto × conns × loss × obf × peers, CSV
SMOKE=1 bench/bench.sh         # быстрый прогон
PLAN_ONLY=1 FORCE=1 bench/bench.sh   # план без трафика (без root)
bench/verify-userspace.sh      # userspace ↔ userspace
MODE=user-first bench/verify-interop.sh   # interop с модулем ядра
bench/verify.sh                # kernel ↔ kernel (umbrawg)
bash bench/tests/test-bench-lib.sh                    # 62 проверки хелперов
python3 -m unittest discover -s bench/tests -p 'test_*.py'   # 17 тестов отчёта
```

Переменные матрицы: `IMPL_LIST`, `MODE_LIST`, `PROTO_LIST`, `CONNS_LIST`, `LOSS_LIST`,
`OBF_LIST`, `PEERS_LIST`, `DURATION`, `SMOKE`, `REPEATS`, `UDP_RATE`, `PLAN_ONLY`,
`FORCE`, `RESULT`, `RUN_ID`, `CPU_HOT_PCT`. Изоляция: туннель на
`TUNNEL_CPUS_1`/`TUNNEL_CPUS_3`, iperf3 на `IPERF_CPU`.

Пути выводятся из расположения `bench.sh`: `BENCH_DIR`, `REPO_ROOT`,
`WORKSPACE_ROOT`, а также `RUSTDIR`, `MODDIR`/`MODULE_DIR`, `UWG`, `DAEMON`,
`GO_BASELINE`, `OBF`, `RESULT`, `REPORT_PY`. Стенд, развёрнутый вне репозитория
(например, `/root/umbrawg/bench`), задаёт их переменными окружения — таблица
значений по умолчанию в `bench/README.md`.

## Известные проблемы

- AdvancedSecurity пира доступен только для чтения: ядро 3.1 выставляет флаг само.
- Пакеты (`debian/`, spec) собираются из Rust-дерева; для source-upload в Debian
  нужен vendor `netlink-packet-umbrawg`.
- CI собирает ARM-тарболы, но не запускает тесты на ARM-хостах.
- `Cargo.lock` синхронен с веткой `main` репозитория `netlink-packet-umbrawg`
  (0.2.1); при сборке против другой ветки (0.3.0) cargo обновляет lock, поэтому
  `--locked` в CI не используется.
- Стенд (netns/insmod/iperf3) в CI не запускается: только `bash -n` и юнит-тесты
  хелперов; реальные замеры — на выделенной машине.
- Go-эталон с обфускацией несравним: в нём обфускация данных — заглушка
  (`device/obf_data.go`), а S4=28 на MTU 1500 вызывает фрагментацию.

## Что делать дальше (по приоритету)

1. Добавить interop-тест Rust↔ядро в CI (в netns, с автоскипом без root).
2. Vendor `netlink-packet-umbrawg` для source-upload в Debian.
3. Проверить первую CI-сборку пакетов на тег `v*` (Arch ждёт версию netlink
   из `Cargo.lock` в ветке `main`) и ARM-рантайм.

Сделано в 0.2.0: упаковка Debian/RPM из `cargo build --release`, man-страницы,
completions, systemd-юниты, CI fmt/clippy/test и релизные сборки x86_64/aarch64/armv7.

## Соглашения

- Байты на проводе, числовые атрибуты netlink и формат UAPI не меняются.
- Коммиты на русском, Conventional Commits; ветки `feature/*`, слияние в `master`.
- `legacy-c/` и `contrib/` — только для сверки, не собираются.
