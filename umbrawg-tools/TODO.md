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
  `uwg show <iface> advanced-security`), ключ `AdvancedSecurity` в `[Peer]`,
  `showconf`/`save`, отправка в ядро через `UWGPEER_A_ADVANCED_SECURITY` и
  передача в userspace UAPI (`advanced_security=1|0`, демон только хранит и
  отдаёт значение).
- Тесты: 219+ (unit, CLI-тесты `uwg` на фейковом UAPI-сокете, CLI-тесты
  `uwg-quick`, контрактный тест `setconf` и parity-тесты `strip` против
  bash-версии); точное число растёт, ориентир — `cargo test --workspace`.
- Коды возврата `uwg`/`uwg-quick` соответствуют legacy `wg`/`awg`: ошибки
  использования и выполнения — 1 (usage в stderr), `--help`/`-h`/`help` и
  `--version`/`-v`/`version` — 0.
- CI: fmt/clippy/test, тесты стенда (`bench`) и статические проверки упаковки
  (`packaging`), релизные сборки x86_64/aarch64/armv7; упаковка
  deb/rpm/man/completions/systemd из Rust-дерева; на тег `tools-v*` —
  `.github/workflows/tools-packaging.yml` собирает `.deb`, `.rpm` и Arch `-git`
  и публикует их в релиз вместе с `SHA256SUMS`.
- Интеграционные скрипты: `scripts/test-kernel.sh`, `scripts/test-userspace.sh`,
  `scripts/test-two-nodes.sh`, `scripts/test-daemon-e2e.sh` — проходят на
  сервере (последний — без модуля ядра, через UAPI).
- Стенд замеров: `bench/bench.sh` (матрица, повторы, MTU-guard, CPU-профиль),
  `bench/bench-report.py` (Markdown + агрегат), тесты стенда в `bench/tests/`,
  `bench/verify*.sh` (проверки userspace↔userspace и userspace↔ядро),
  `bench/obf-params.conf`. Пути к соседним репозиториям не зашиты: см.
  `bench/README.md`.
- Итоговые результаты замеров final5 (2026-11-17) зафиксированы в
  `docs/RESULTS.md`.
- Бенчмарк-матрица 2026-11-21 (baseline AmneziaWG, потери, FEC, BBR удалён
  в 0.5.0, UDP, RTT, cipher, обфускация, multi-peer) —
  [`../docs/BENCHMARKS-2026-11-21.md`](../docs/BENCHMARKS-2026-11-21.md);
  сырые артефакты — `/root/bench-matrix/{v2,v3,aes,obf,multi}`.
- UDP-диагностика: правильная методика — `iperf3 -w 8M` на клиенте и
  `rmem_max ≥ 8 МиБ`, счётчики `ss`/`nstat` (`UdpRcvbufErrors`), TUN
  байты/segments и `tc -s qdisc`. При дефолтном `-w` Rust теряет 0.154%
  даже на чистом канале, ядро — 0.000%; с `-w 8M` — 0 у обоих.
- FEC RTT после исправлений: kernel `2:1` 1.099 мс (было 5.05–5.56),
  Rust 0.343 (было 3.7–3.9), mixed 0.727; slow-link `8:2` — 0% при
  `offered ≤ 0.4 × R`, 0.6 × R даёт 7–9% у ядра и до ~1% у Rust.
- FEC: `uwg set/show fec|underlay-mtu`, `uwg show <if> fec-stats` для обоих
  бэкендов; fixed-профили `K=1..8, M=1..2`, adaptive по умолчанию. BBR и
  `bbr-stats` удалены в 0.5.0.
- Env: `WG_COLOR_MODE`/`WG_HIDE_KEYS` — основные, `UWG_COLOR_MODE`/
  `UWG_HIDE_KEYS` — deprecated fallback.
- Статические проверки упаковки: `scripts/check-packaging.sh` (версии,
  man-страницы, systemd-юниты, completions, YAML, артефакты в правилах
  сборки), job `packaging` в CI.
- Единый troubleshooting по реальным сбоям (handshake, MTU и фрагментация,
  сборка модуля и DKMS, упаковка, `uwg`/`uwg-quick`, параллельный RX,
  отладка) — [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md), ссылка из
  README.

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
Переменные окружения: `UWG_QUICK_USERSPACE_IMPLEMENTATION`, `WG_COLOR_MODE`,
`WG_HIDE_KEYS` (legacy `UWG_COLOR_MODE`/`UWG_HIDE_KEYS` — fallback),
`UWG_RUNTIME_DIR`.

## Стенд (bench/)

```sh
bench/bench.sh                 # матрица: impl × mode × proto × conns × loss × obf × peers, CSV
SMOKE=1 bench/bench.sh         # быстрый прогон
PLAN_ONLY=1 FORCE=1 bench/bench.sh   # план без трафика (без root)
bench/verify-userspace.sh      # userspace ↔ userspace
MODE=user-first bench/verify-interop.sh   # interop с модулем ядра
bench/verify.sh                # kernel ↔ kernel (umbrawg)
bash bench/tests/test-bench-lib.sh                    # 72 проверки хелперов
python3 -m unittest discover -s bench/tests -p 'test_*.py'   # тесты отчёта, сравнения и detect
```

Переменные матрицы: `IMPL_LIST`, `MODE_LIST`, `PROTO_LIST`, `CONNS_LIST`, `LOSS_LIST`,
`OBF_LIST`, `PEERS_LIST`, `DURATION`, `SMOKE`, `REPEATS`, `UDP_RATE`, `PLAN_ONLY`,
`FORCE`, `RESULT`, `RUN_ID`, `CPU_HOT_PCT`. Изоляция: туннель на
`TUNNEL_CPUS_1`/`TUNNEL_CPUS_3`, iperf3 на `IPERF_CPU`.

Пути выводятся из расположения `bench.sh`: `BENCH_DIR`, `REPO_ROOT`,
`WORKSPACE_ROOT`, а также `RUSTDIR`, `MODDIR`/`MODULE_DIR`, `UWG`, `DAEMON`,
`GO_BASELINE`, `OBF`, `RESULT`, `REPORT_PY`. Стенд, развёрнутый вне
монорепозитория, задаёт их переменными окружения — таблица значений по
умолчанию в `bench/README.md`.

## Известные проблемы

- `AdvancedSecurity` через userspace UAPI — информационный: демон хранит и
  отдаёт значение, но не применяет его; реально его включает только модуль ядра
  (`UWGPEER_A_ADVANCED_SECURITY`).
- Пакеты (`debian/`, spec) собираются из Rust-дерева; для source-upload в Debian
  нужен vendor `netlink-packet-umbrawg`.
- CI собирает ARM-тарболы, но не запускает тесты на ARM-хостах.
- `Cargo.lock` синхронен с веткой `main` репозитория `netlink-packet-umbrawg`
  (0.4.1); при сборке против другой ветки cargo обновляет lock, поэтому
  `--locked` в CI не используется.
- Стенд (netns/insmod/iperf3) в CI не запускается: только `bash -n` и юнит-тесты
  хелперов; реальные замеры — на выделенной машине.
- UDP на дефолтном `iperf3 -w` измеряет буфер приёмника, а не туннель:
  Rust теряет 0.154% даже на чистом канале. Для замеров обязательны
  `-w 8M` и `rmem_max ≥ 8 МиБ`; в `bench.sh` это пока не зашито (п. 8).
- Go-эталон удалён из монорепо (`96dc33d8`) и в матрице 2026-11-21 не
  участвует; сравнение — только с внешними `amneziawg`/`amneziawg-go`.
  При этом дефолт `IMPL_LIST` в `bench.sh` всё ещё содержит `go`, поэтому
  прогон после удаления форка требует явного `IMPL_LIST`. Прежняя оговорка
  про заглушку обфускации в Go остаётся в истории final5.

## Что делать дальше (по приоритету)

1. Добавить interop-тест Rust↔ядро в CI (в netns, с автоскипом без root).
2. Vendor `netlink-packet-umbrawg` для source-upload в Debian.
3. Проверить первую CI-сборку пакетов на тег `tools-v*` (Arch ждёт версию
   netlink из `Cargo.lock` в ветке `main`) и ARM-рантайм.
4. Поставить компонентные теги `tools-v0.4.1` и `netlink-v0.4.1`;
   до публикации — `updpkgsums` для стабильных Arch-пакетов.
5. Матрица cipher: `AES-256-GCM` и mixed ChaCha/AES снята на 1/5/50 пирах
   (`/root/bench-matrix/aes`: kernel +10.8…+29%, Rust +13.9…+35% к ChaCha),
   но `CIPHER` всё ещё не ось `bench.sh` — добавить ось и воспроизвести §5
   матрицы штатным стендом.
6. Multi-peer 5/10/50 снят (`/root/bench-matrix/multi`), 100 не тестировались
   (у Rust прогноз ~4.5 ГБ, у `awg-go` 50 недостижимы). В `bench.sh` дефолт
   по-прежнему 1/4 пира — расширить `PEERS_LIST` и добавить сбор RSS/fairness
   в отчёт.
7. Зафиксировать методику v2/v3 и артефакты `/root/bench-matrix/{v2,v3,aes,obf,multi}`;
   сослаться на них из `docs/BENCHMARKS-2026-11-21.md`.
8. **UDP-диагностика — причина закрыта, методика — нет.** 0.08–0.1% потерь
   Rust на чистом канале — дефолтное окно `iperf3 -w` (0.154% против 0 при
   `-w 8M`), а не дропы туннеля. Осталось зашить `-w 8M`/`rmem_max` и
   счётчики `ss`/`nstat`/TUN в штатный `bench.sh`, чтобы отчёт не смешивал
   `RcvbufErrors` с потерями канала.
9. **Slow-link и rate-adaptive batching.** Добавить ось полосы
   (10/25/50 Мбит) и профиль `2:1`/`4:2`/`8:2`; проверить
   `offered ≤ 0.4 × R` и `R·k/(k+m)`, зафиксировать, где частичные блоки
   `k'=1, m'=2` упираются в rate-лимит. Идея — rate-adaptive batching:
   окно накопления растёт на медленном канале.
10. Убрать `go` из дефолта `IMPL_LIST` или явно помечать его как
    отсутствующий: после удаления Go-форка прогон без явного `IMPL_LIST`
    пытается запустить несуществующий бинарник.
11. Mixed fairness/шейпинг: mixed на 2% ниже чистого AES на 11–13%
    (1.421/1.438 против 1.627/1.625) — добавить в отчёт стенда fairness и
    проверить шейпер при разных cipher на концах.

Сделано в 0.2.0–0.4.1: упаковка Debian/RPM из `cargo build --release`,
man-страницы, completions, systemd-юниты, CI fmt/clippy/test, релизные сборки
x86_64/aarch64/armv7, FEC/underlay-mtu и статистика для обоих бэкендов
(BBR удалён в 0.5.0).

## Соглашения

- Байты на проводе, числовые атрибуты netlink и формат UAPI не меняются.
- Коммиты на русском, Conventional Commits; ветки `feature/*`, слияние в `master`.
- `legacy-c/` и `contrib/` — только для сверки, не собираются.
