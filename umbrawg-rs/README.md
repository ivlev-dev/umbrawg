# UmbraWG userspace (Rust)

![CI](https://github.com/ivlev-dev/umbrawg-rs/actions/workflows/ci.yml/badge.svg) ![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)

Userspace daemon for the UmbraWG protocol (WireGuard-compatible Noise IK with
UmbraWG 3.1 obfuscation). Wire-compatible with the `umbrawg` kernel module.

## Workspace

| Crate | Purpose |
|---|---|
| `umbrawg-crypto` | BLAKE2s, ChaCha20-Poly1305, X25519, TAI64N |
| `umbrawg-proto` | messages, framing, obfuscation parameters and transforms |
| `umbrawg-noise` | Noise IK handshake, cookies |
| `umbrawg-device` | device/peer state machine, allowed-ips, replay, ratelimiter, timers |
| `umbrawg-transport` | UDP sockets, GSO/GRO, batching |
| `umbrawg-tun` | TUN device, multi-queue, virtio-net offload |
| `umbrawg-uapi` | UAPI server (`/var/run/umbrawg/<iface>.sock`) |
| `umbrawg-bench` | criterion micro-benchmarks |
| `umbrawg` | daemon binary |

## Build

```sh
cargo build --release -p umbrawg
cargo build --release --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The minimum supported Rust version is 1.88 (`rust-version` in the manifests,
enforced by the `msrv` CI job). The daemon depends on Linux only: `libc`,
`rustix` (`fs`) and `/dev/net/tun`; there is no dependency on the netlink crate
or the kernel module.

`.cargo/config.toml` sets `--cfg poly1305_force_soft` for x86/x86_64. On
MTU-sized packets the scalar Poly1305 backend is faster: the AVX2 backend pays a
large per-message setup cost that only amortises above ~8 KiB. The flag changes
no bytes on the wire.

### Cross build (ARM)

Supported release targets: `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, `armv7-unknown-linux-gnueabihf`. Cross linking
uses the distribution cross toolchains:

```sh
rustup target add aarch64-unknown-linux-gnu armv7-unknown-linux-gnueabihf
sudo apt-get install gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
    gcc-arm-linux-gnueabihf libc6-dev-armhf-cross
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc
cargo build --release -p umbrawg --target aarch64-unknown-linux-gnu
cargo build --release -p umbrawg --target armv7-unknown-linux-gnueabihf
```

`libc6-dev-*-cross` is required: without it the cross linker fails with
`cannot find Scrt1.o`/`crti.o`. The resulting binaries are dynamically linked
PIE, so the target system needs a matching arm64/armhf userland. Verification
in Docker (`rust:bookworm`, glibc 2.36) shows a maximum requirement of
`GLIBC_2.34` for all three targets, which covers Debian 12 (bookworm) and
Raspberry Pi OS bookworm; systems on glibc 2.31 (bullseye) need a rebuild in a
matching container. CI builds on Ubuntu 22.04 (libc 2.35), so the produced
archives require at most glibc 2.35.

Verification without hardware:

```sh
file target/aarch64-unknown-linux-gnu/release/umbrawg
readelf -h target/aarch64-unknown-linux-gnu/release/umbrawg
readelf -V target/aarch64-unknown-linux-gnu/release/umbrawg
qemu-aarch64-static -L /usr/aarch64-linux-gnu target/aarch64-unknown-linux-gnu/release/umbrawg --version
qemu-arm-static -L /usr/arm-linux-gnueabihf target/armv7-unknown-linux-gnueabihf/release/umbrawg --version
```

## CI

`.github/workflows/ci.yml`:

| Job | Contents |
|---|---|
| `deny` | `cargo deny check` (политика зависимостей, `deny.toml`) |
| `test stable` | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`, `cargo doc -D warnings` |
| `msrv 1.88` | `cargo build --workspace` and `cargo test --no-run` on the declared minimum toolchain |
| `build <target>` | release build of `umbrawg` for all three targets, tests compiled for the target, `file`/`readelf` architecture check, qemu smoke run of the binary and unit tests under qemu, packaged `tar.gz` artifact |
| `data-plane e2e` | two daemons in two network namespaces over a veth pair: handshake, ping, iperf3, 32 MiB integrity check in the obfuscation × parallel-RX matrix; `SKIP` when TUN, `unshare -Urn` or `uwg` is unavailable |
| `GitHub Release` | on a `v*` tag: `SHA256SUMS` and the archives are published |

The build job runs on Ubuntu 22.04 to keep the produced binaries usable on older
userlands. Each archive is a relocatable tree:

```text
umbrawg-<version>-<target>/
  usr/bin/umbrawg
  usr/share/doc/umbrawg/{README.md,CHANGELOG.md,LICENSE}
  usr/lib/systemd/system/*.service   (only if systemd/ exists in the repository)
```

The `umbrawg@.service` unit currently ships with the `umbrawg-tools` package
(`systemd/umbrawg@.service`), so the daemon archive contains only the binary.

### Packaging (`packaging.yml`)

`.github/workflows/packaging.yml` builds distribution packages and does not
duplicate the `tar.gz` archives from `ci.yml`:

| Job | Image | Contents |
|---|---|---|
| `arch` | `archlinux:latest` | `makepkg -f --noconfirm --nodeps` for `contrib/arch/umbrawg-daemon-git` (runs the PKGBUILD `check()`), then verifies the package: `/usr/bin/umbrawg`, `usr/lib/systemd/system/umbrawg@.service`, `usr/lib/tmpfiles.d/umbrawg.conf` (`d /run/umbrawg 0700 root root -`), `/etc/umbrawg` mode `0700`, and `umbrawg --version` executed straight from the unpacked tree |
| `релиз` | `ubuntu-latest` | on a `v*` tag: `.pkg.tar.zst` and `SHA256SUMS.pkg` in the GitHub Release |

Release mechanics:

- the tag has to match `v<version>` from `Cargo.toml` (`v0.1.0` right now);
  `workflow_dispatch` takes an optional `version` input for a manual check;
- no secrets are needed — the AUR upload stays manual;
- the release job uses `concurrency: release-<ref>` with `cancel-in-progress:
  false`. The `GitHub Release` job in `ci.yml` still has no concurrency group,
  so a single tag can start both release steps at once; adding the same group
  there is tracked in `TODO.md`;
- checksum files are kept apart: `ci.yml` publishes `SHA256SUMS` for the
  `tar.gz` archives, `packaging.yml` publishes `SHA256SUMS.pkg` for the Arch
  package, so neither step overwrites the other's asset;
- the stable Arch package `contrib/arch/umbrawg-daemon` is not built in CI: its
  `sha256sums` is a placeholder and needs `updpkgsums` after the first tag.

## Run

```sh
umbrawg uwg0
```

Configure with `uwg` from `umbrawg-tools` (kernel module and userspace share the
same CLI and configuration format).

## Переменные окружения

| Имя | По умолчанию | Смысл |
|---|---|---|
| `UMBRAWG_THREADS` | `min(4, доступные ядра)` | Число воркеров однопоточного режима. Каждый воркер владеет отдельной очередью TUN и UDP-сокетом с `SO_REUSEPORT`. Игнорируется при включённом `UMBRAWG_PARALLEL_RX`. |
| `UMBRAWG_PARALLEL_RX` | выключено (`0`/не задано) | `1` (или `true`/`yes`/`on`) включает параллельный приём: RX-поток `recvmmsg` + крипто-воркеры. |
| `UMBRAWG_RX_WORKERS` | половина ядер, не более 4 (на 6 vCPU = 3) | Число крипто-воркеров параллельного приёма. |
| `UMBRAWG_RX_SCHED` | `peer` | Выбор крипто-воркера: `peer` — привязка по публичному ключу пира (порядок внутри пира сохраняется), `queue` — наименее загруженная очередь (для замеров, переставляет пакеты одного потока). |
| `UMBRAWG_RX_QUEUE` | `256` | Глубина очереди заданий и пула буферов каждого крипто-воркера: степень двойки от 64 до 1024. Один слот — до 64 КиБ, поэтому на воркера уходит 64 → ~4 МиБ, 256 → ~16 МиБ, 1024 → ~64 МиБ. Некорректное значение (не число, вне диапазона, не степень двойки) — ошибка при старте. Действует при `UMBRAWG_PARALLEL_RX=1`. |
| `UMBRAWG_RX_STATS` | выключено (`0`/не задано) | `1` включает вывод счётчиков приёма каждые 5 секунд (пакеты, батчи, сегменты, GRO/GSO, дропы, пробуждения, `under_load`, `control_drops`). |
| `UMBRAWG_UNDER_LOAD_PPS` | `100` | Порог детектора флуда: валидных по MAC1 инициаций в секунду, после которого включается cookie-защита. Нулевые и некорректные значения заменяются значением по умолчанию. |
| `UMBRAWG_UNDER_LOAD` | включено | `0`, `false`, `no` или `off` выключает автоматический детектор (флаг `under_load` остаётся снятым). Только для замеров и отладки: без детектора инициации обрабатываются без cookie. |
| `UMBRAWG_LOG_LEVEL` | `info` | Уровень логирования (`trace`, `debug`, `info`, `warn`, `error`). |
| `UMBRAWG_RUNTIME_DIR` | `/var/run/umbrawg` | Каталог unix-сокетов UAPI (`<iface>.sock`). При задании копируется в `UWG_RUNTIME_DIR` для совместимости с `umbrawg-tools`. |
| `UWG_RUNTIME_DIR` | `/var/run/umbrawg` | То же, что `UMBRAWG_RUNTIME_DIR`, читается сервером UAPI напрямую (совместимость с `uwg`/`uwg-quick`). |

## Параллельный приём

> **Экспериментальный режим.** `UMBRAWG_PARALLEL_RX=1` медленнее обычного
> однопоточного rust на 7.2–17.9% на одном пире в 7 из 8 ячеек матрицы final4
> (единственное исключение — 3c c=1 obf=1, +4.8%) и на 8.8%/15.6% в multi-peer
> (obf=0/1); см. раздел «Производительность» и
> [tools/docs/RESULTS.md](tools/docs/RESULTS.md). Цели +30%/+60% не достигнуты.
> **Не рекомендуется включать по умолчанию** (`default-on`); режим остаётся
> opt-in для multi-peer сценариев и замеров.

Включается переменной `UMBRAWG_PARALLEL_RX=1` (по умолчанию выключен). Опционально:
`UMBRAWG_RX_WORKERS=N`, `UMBRAWG_RX_SCHED=peer|queue`, `UMBRAWG_RX_QUEUE=N`,
`UMBRAWG_RX_STATS=1`.

Что меняется:

- один поток приёма делает `recvmmsg`, классификацию сообщения и поиск сессии,
  раскладывая дейтаграммы по SPSC-очередям крипто-воркеров;
- крипто-воркеры (`N`) выполняют расшифровку, проверку повтора (`AtomicReplayFilter`)
  и запись в собственные очереди TUN с GSO-склейкой;
- воркер выбирается по пиру: `hash(public_key) % N` (FNV-1a). Все транспортные
  сегменты одного пира попадают в один воркер, поэтому порядок пакетов внутри
  пира сохраняется, а разные пиры распределяются по воркерам. Состояние сессии
  (replay-фильтр, таймеры) пира при этом трогает только один воркер;
- дейтаграмма (включая GRO-суперпакет) целиком уходит одному воркеру: воркер
  определяет первый транспортный сегмент, остальные сегменты (в том числе
  аномальный случай с разными пирами в одной GRO-дейтаграмме) идут в то же
  задание и не теряются; такие дейтаграммы считает счётчик `mixed_peers`;
- управляющие пакеты (рукопожатие, cookie) классифицируются потоком приёма и
  копируются в ограниченную очередь (128 пакетов), которую разбирает отдельный
  поток `umbrawg-control`; поток приёма не ждёт X25519 и не блокирует данные;
- переполнение: если очередь выбранного пиром воркера заполнена, дейтаграмма
  дропается со счётчиком `drops(queue)`, а не перекидывается на другой воркер —
  иначе порядок сломался бы. Пир на другом воркере от этого не страдает:
  у каждого пира своя привязка.

### Глубина очереди и память

`UMBRAWG_RX_QUEUE` задаёт глубину очереди заданий и пула буферов каждого
воркера. Допустимы степени двойки от 64 до 1024, по умолчанию 256 (прежнее
поведение). Один слот — `MAX_PACKET` = 65 535 байт, поэтому буферы воркера
занимают `глубина × 65 535` байт:

| `UMBRAWG_RX_QUEUE` | На воркера | 4 воркера |
|---|---|---|
| 64 | 4 194 240 Б (~4 МиБ) | ~16 МиБ |
| 128 | 8 388 480 Б (~8 МиБ) | ~32 МиБ |
| 256 (по умолчанию) | 16 776 960 Б (~16 МиБ) | ~64 МиБ |
| 512 | 33 553 920 Б (~32 МиБ) | ~128 МиБ |
| 1024 | 67 107 840 Б (~64 МиБ) | ~256 МиБ |

Сверху — служебные SPSC-кольца (задания, свободные слоты), порядка сотен КиБ
на воркера. Глубокая очередь нужна, чтобы привязка по пиру (`peer`) не теряла
дейтаграммы на всплесках; при уменьшении глубины растёт `drops(queue)` в
счётчиках `UMBRAWG_RX_STATS=1`. Некорректное значение (не число, вне диапазона,
не степень двойки) — ошибка при старте демона, а не молчаливый clamp.

Режим `UMBRAWG_RX_SCHED=queue` (для замеров) раскладывает задания по наименее
загруженной очереди. Он даёт большую суммарную скорость на одном потоке, но
переставляет пакеты между воркерами и вызывает ретрансмиты TCP; по умолчанию
не используется.

Ограничения и компромиссы:

- порядок пакетов между разными пирами не гарантируется (каждый пир — свой воркер);
- пропускная способность одного пира ограничена одним воркером, то есть близка
  к однопоточному режиму; выигрыш даёт сумма пиров;
- память задаётся `UMBRAWG_RX_QUEUE` (по умолчанию ~16 МиБ буферов на воркера:
  256 слотов по 64 КиБ); глубокая очередь нужна, чтобы приём не терял
  дейтаграммы на всплесках при привязке по пиру;
- очередь управляющих пакетов ограничена: при флуде сверх 128 ожидающих
  пакетов новые отбрасываются со счётчиком `control_drops`, данные при этом
  продолжают идти;
- режим opt-in; перевод в default-on требует soak-тестирования на реальном
  NIC и ARM.

Счётчики при `UMBRAWG_RX_STATS=1` выводятся в лог раз в 5 секунд: режим
(`sched`), дейтаграммы, сегменты, GRO-разбиения, управляющие пакеты и их дропы
(`control_drops`), флаг `under_load`, `mixed_peers`, дропы (классификация,
подготовка, переполнение очереди, размер, TUN, передача), пробуждения воркеров.

## Защита от флуда управляющих пакетов

Детектор `under_load` включён по умолчанию и работает в обоих режимах приёма.
Он считает инициации рукопожатия, прошедшие MAC1, в скользящем окне 1 секунда
(в параллельном режиме сами управляющие пакеты дополнительно вынесены из
RX-потока; в однопоточном защита ограничивается cookie и rate limiter):

- вход в `under_load` — при достижении `UMBRAWG_UNDER_LOAD_PPS` (по умолчанию
  100 инициаций/с);
- выход — когда частота опускается ниже половины порога (гистерезис), окно
  пересчитывается в цикле housekeeping и в потоке управления;
- выключение — `UMBRAWG_UNDER_LOAD=0` (для замеров; по умолчанию защита
  включена).

Пока `under_load` установлен, обработчик инициации до дорогой криптографии:

1. проверяет MAC2 (cookie) для адреса отправителя; без валидного MAC2
   отправляется cookie-ответ и пакет дальше не обрабатывается;
2. после валидного MAC2 применяет существующий rate limiter — не более
   20 инициаций в секунду на адрес (IPv6 — на `/64`).

Cookie-механизм не меняет проводной формат и совместим с WireGuard/UmbraWG:
используются штатные `CookieChecker`/`CookieGenerator` и сообщение cookie.
Если в конфигурации обфускации задан `DisableCookies`, cookie-ответы не
отправляются; в этом случае остаётся только ограничение очереди управления и
внешний rate limit.

Детектор не заменяет межсетевой экран и ограничение частоты на границе сети:
он снижает стоимость неаутентифицированного флуда для демона, но не убирает
сам трафик из канала.

Флуд-сценарий: `scripts/test-control-flood.sh` поднимает два демона в
network namespace и сравнивает пропускную способность TCP во время потока
инициаций с включённым детектором и с `UMBRAWG_UNDER_LOAD=0`, проверяя
отсутствие дропов данных и появление `under_load=1` в счётчиках. Перед запуском
соберите генератор:

```sh
cargo build --release --example initiation_flood -p umbrawg-device
```

Отключить: не задавать `UMBRAWG_PARALLEL_RX` или установить значение, отличное
от `1`/`true`/`yes`/`on` (по умолчанию однопоточный режим, который не деградирует
на одном соединении).

## Производительность

Финальные замеры (final4, сервер 6 vCPU, MTU 9000, 3 повтора) — полная матрица
и методика в [tools/docs/RESULTS.md](tools/docs/RESULTS.md). Fast-path (TUN offload,
GSO/GRO, `sendmmsg`/`recvmmsg`) дал прирост +12.6…+103% относительно исходной
userspace-реализации (final3), а GSO-фикс обфускации ускорил `obf=1` в 1.8–2.8
раза.

Ключевые цифры (TCP, Мбит/с, медиана 3 повторов):

| Сценарий | kernel | rust | go |
|---|---|---|---|
| 1c, c=1, obf=0 | 2345 | 1527 | 2058 |
| 1c, c=1, obf=1 | 2268 | **1439** | 1984 |
| 1c, c=10, obf=0 | 2100 | 1505 | 1635 |
| 1c, c=10, obf=1 | 1767 | **1377** | 1708 |
| 3c, c=1, obf=0 | 2430 | 2049 | 3633 |
| 3c, c=1, obf=1 | 2253 | **1622** | 3032 |
| 3c, c=10, obf=0 | 2056 | 2257 | 4724 |
| 3c, c=10, obf=1 | 1875 | **2093** | 4328 |
| 4 пира, 3c, c=10, obf=0 | 4986 | 3919 | 4664 |
| 4 пира, 3c, c=10, obf=1 | 4651 | 3823 | 4492 |

UDP: после GSO-фикса `rust` держит линию 1G во всех ячейках (999.4–999.8,
потери ≤0.03%), кроме 1c c=10 obf=1 (981.5, 1.8%); `obf=0` не регрессировал.

Где обгоняем: на 3c c=10 rust (2257) обгоняет kernel (2056) и amneziawg (1682)
на +9.8%/+34.2% при obf=0; при obf=1 — 2093 против 1875 и 1681 (+11.6%/+24.5%).
На 3c c=1 obf=0 rust (2049) на +8.5% к amneziawg (1888).
Где отстаём: 1c — 1527/1439 против 2345/2268 у ядра (22–37% ниже) и против
2058/1984 у go; 3c против go — 44–52% ниже; multi-peer — 16–22% ниже лидеров.
После GSO-фикса `obf=1` больше не проваливается в 2–3 раза.

Параллельный приём (`UMBRAWG_PARALLEL_RX=1`) — экспериментальный: на одном пире
он медленнее обычного rust на 7.2–17.9% в 7 из 8 ячеек матрицы (исключение —
3c c=1 obf=1, +4.8%) и на 8.8%/15.6% в multi-peer; цели +30%/+60% не
достигнуты. Рекомендуется оставлять выключенным по умолчанию; включать только
для multi-peer сценариев и замеров. Подробнее — раздел «Параллельный приём» и
[tools/docs/RESULTS.md](tools/docs/RESULTS.md).

Ядро (`kernel-umbrawg`) на c=1 достигло +33.0% (1c obf=1) и +33.2% (3c obf=1)
к `kernel-amneziawg`; на obf=0 — +25.3%/+28.7%.

## Data-plane e2e

`scripts/test-dataplane-e2e.sh` проверяет не UAPI, а сам путь данных: два
демона в двух network namespace, соединённых veth-парой, поднимают TUN
`uwgA` (`10.71.0.1/24`) и `uwgB` (`10.71.0.2/24`), обмениваются рукопожатием
и гоняют трафик через туннель.

Что проверяется в каждом прогоне:

- рукопожатие по `uwg show <iface> latest-handshakes` (инициируется пингом);
- `ping` между `10.71.0.1` и `10.71.0.2`;
- `iperf3` TCP 3 с и UDP 200 Мбит/с 2 с, фиксируются скорость, потери и число
  ретрансмитов TCP (колонка `Retr` в отчёте `iperf3`);
- целостность: файл 32 МиБ передаётся через туннель (`nc`), sha256 источника
  и получателя сравниваются;
- в логах демонов нет `ERROR`, `panicked`, `worker stopped`, `parallel rx failure`;
- при `UMBRAWG_RX_STATS=1` (счётчики печатаются только в параллельном режиме)
  дропы нулевые или объяснимые: `prepared` на отвечающей стороне — это
  pre-handshake specials `I1-I5` и Jc-джанк (по 9 пакетов на инициацию),
  `queue` — переполнение приёмной очереди под нагрузкой (не более 1 %
  дейтаграмм).

Матрица: `UMBRAWG_PARALLEL_RX=0|1` × `obf=0|1`, четыре прогона. `obf=1` — полный
профиль 3.1: `Jc/Jmin/Jmax`, `S1-S4`, `H1-H4`, `I1-I5`,
`HeaderProtectionKey`, `ContentPaddingAddition`, `RandomTrailers`. `obf=0` —
чистый WireGuard-совместимый режим.

```sh
cargo build --release -p umbrawg
# uwg из umbrawg-tools
UWG=../umbrawg-tools/target/release/uwg \
  DAEMON=target/release/umbrawg \
  bash scripts/test-dataplane-e2e.sh
```

Root не нужен: скрипт перезапускает себя через `unshare -Urn`. Если TUN,
veth, `unshare`, `nsenter` или `uwg` недоступны, печатается `SKIP` и код
возврата 0 — это поведение использует job `data-plane e2e` в CI.

Переменные: `UWG`, `DAEMON`, `FILE_MIB` (32), `HANDSHAKE_TIMEOUT` (20),
`MIN_TCP_MBIT` (0 — без порога), `CASES` (подмножество `obf0p0 obf0p1 obf1p0
obf1p1`), `UWB_DP_QUICK=1` (только два прогона с `obf=1`),
`UMBRAWG_RX_SCHED=peer|queue`, `KEEP_ARTIFACTS=1` (оставить каталог с логами и
файлами), `IFACE_A`/`IFACE_B`, `PORT_A`/`PORT_B`, `UNDERLAY_*`, `TUN_*`.

Прогон final4 (сервер 6 vCPU, veth, underlay MTU 1500, `sched=peer`):

| Прогон | parallel | obf | iperf3 TCP | Ретрансмиты | iperf3 UDP | Дропы |
|---|---|---|---|---|---|---|
| `obf0-par0` | 0 | 0 | 2207 Мбит/с | 0 | 200 Мбит/с, 0/36568 | n/a (нет stats) |
| `obf0-par1` | 1 | 0 | 2106 Мбит/с | 58 | 200 Мбит/с, 0/36564 | `queue=43` (B) |
| `obf1-par0` | 0 | 1 | 883 Мбит/с | 8004 | 200 Мбит/с, 0/36567 | n/a (нет stats) |
| `obf1-par1` | 1 | 1 | 780 Мбит/с | 7169 | 200 Мбит/с, 0/36557 | `prepared=9` (specials) |

Во всех прогонах ping без потерь, sha256 файла 32 МиБ совпал.

Привязка по пиру (`peer`, по умолчанию) убирает перестановку: на одном пире
скорость совпадает с однопоточным режимом, ретрансмитов нет (`obf=0`).
`queue` остаётся для замеров: в ранних прогонах суммарная скорость была выше,
но TCP видел перестановку и массово ретранслировал. При `obf=1` ретрансмиты
есть и в однопоточном режиме (путь обфускации в veth-стенде упирается в CPU),
поэтому `peer` сравнивается с `par0`, а не с нулём.

Несколько пиров: `scripts/test-dataplane-multipeer.sh` поднимает хаб и 2–4 пира
(отдельные netns и veth-пары), каждый пир гонит свой TCP-поток в хаб, затем
сверяется sha256 файла на каждом пире.

```sh
OBF=0 PEERS=3 UMBRAWG_RX_SCHED=peer \
  UWG=../umbrawg-tools/target/release/uwg \
  DAEMON=target/release/umbrawg \
  bash scripts/test-dataplane-multipeer.sh
```

Прогон на 12-ядерном хосте, 3 пира, 3 с на поток:

| sched | obf | По пирам, Мбит/с | Сумма | Ретрансмиты |
|---|---|---|---|---|
| `peer` | 0 | 1520 / 1238 / 2504 | 5262 Мбит/с | 0 |
| `queue` | 0 | 2382 / 2408 / 2390 | 7180 Мбит/с | 40 828 |
| `peer` | 1 | 693 / 719 / 678 | 2090 Мбит/с | 53 806 |
| `queue` | 1 | 1138 / 1138 / 945 | 3221 Мбит/с | 156 171 |

`peer` масштабируется по числу пиров (каждый пир — свой воркер) и сохраняет
порядок: 0 ретрансмитов против 40 828 у `queue` при `obf=0`. Разброс скоростей
между прогонами — шум хоста (на нём параллельно идёт сборка), важен порядок
величин и ретрансмиты.

## Сеть

Демон открывает UDP-сокет в семействе IPv4 (`AddressFamily::Ipv4`); IPv6-транспорт
в крейте `umbrawg-transport` реализован, но демоном не подключён — конечные точки
IPv6 не обслуживаются. TUN и обработка пакетов поддерживают IPv6 на уровне
данных, но отправка/приём UDP идут через IPv4.

## UAPI: `advanced_security`

Демон принимает ключ `advanced_security` в `set=1` для пира (`on`/`off`,
`true`/`false`, `1`/`0`) и возвращает `advanced_security=1|0` в `get=1`, если
значение было задано. Поле информационное: userspace-демон не реализует
advanced security и не меняет обработку пакетов или таймеры. Для реального
включения нужен модуль ядра. Если значение не задавалось, строка в `get=1` не
выводится — это сохраняет совместимость с Go-клиентами и `uwg`.

## systemd

Юнит-шаблон `systemd/umbrawg@.service` запускает демон для интерфейса `%i`:

```sh
systemctl enable --now umbrawg@wg0.service
```

Демон требует `CAP_NET_ADMIN` (создание TUN, настройка маршрутов/адресов через
Netlink). Юнит выдаёт только эту capability (`AmbientCapabilities`/
`CapabilityBoundingSet`) и включает `NoNewPrivileges`. Доступ к устройствам
ограничен `DevicePolicy=closed`; единственное разрешённое физическое устройство —
`/dev/net/tun` (`DeviceAllow`), псевдо-устройства (`/dev/null`, `/dev/urandom`)
разрешаются политикой `closed`. `PrivateDevices` намеренно не используется:
приватный `/dev` не содержит `/dev/net/tun`, и демон не смог бы открыть TUN.

Ограничения: `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
только Unix/IPv4/IPv6/Netlink сокеты, запись разрешена в `/run/umbrawg` и
`/etc/umbrawg`. Бинарник ожидается в `/usr/bin/umbrawg`.

## Документация для разработчика

Состояние проекта и план работ — в [TODO.md](TODO.md).
Архитектура — в [DESIGN.md](DESIGN.md).
Порядок выпуска всех четырёх репозиториев — в
[RELEASE.md](https://github.com/ivlev-dev/umbrawg-tools/blob/master/RELEASE.md).

## Status

The Go implementation that this workspace replaces remains in the git history
(`master`) as a behavioural reference. Obfuscation (H1-H4, S1-S4, Jc/Jmin/Jmax,
I1-I5, header protection, content padding, random trailers) is implemented in
`umbrawg-proto` and exercised by tests in `umbrawg-device`.
