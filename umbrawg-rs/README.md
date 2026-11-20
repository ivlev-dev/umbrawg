# UmbraWG userspace (Rust)

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Version](https://img.shields.io/badge/version-0.3.0-blue.svg)

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

`../.github/workflows/rs-ci.yml`:

| Job | Contents |
|---|---|
| `deny` | `cargo deny check` (политика зависимостей, `deny.toml`) |
| `test stable` | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`, `cargo doc -D warnings` |
| `msrv 1.88` | `cargo build --workspace` and `cargo test --no-run` on the declared minimum toolchain |
| `build <target>` | release build of `umbrawg` for all three targets, tests compiled for the target, `file`/`readelf` architecture check, qemu smoke run of the binary and unit tests under qemu, packaged `tar.gz` artifact |
| `data-plane e2e` | two daemons in two network namespaces over a veth pair: handshake, ping, iperf3, 32 MiB integrity check in the obfuscation × parallel-RX matrix; `SKIP` when TUN, `unshare -Urn` or `uwg` is unavailable |
| `GitHub Release` | on a `rs-v*` tag: `SHA256SUMS` and the archives are published |

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

### Packaging (`rs-packaging.yml`)

`../.github/workflows/rs-packaging.yml` builds distribution packages and does not
duplicate the `tar.gz` archives from `rs-ci.yml`:

| Job | Image | Contents |
|---|---|---|
| `arch` | `archlinux:latest` | `makepkg -f --noconfirm --nodeps` for `contrib/arch/umbrawg-daemon-git` (runs the PKGBUILD `check()`), then verifies the package: `/usr/bin/umbrawg`, `usr/lib/systemd/system/umbrawg@.service`, `usr/lib/tmpfiles.d/umbrawg.conf` (`d /run/umbrawg 0700 root root -`), `/etc/umbrawg` mode `0700`, and `umbrawg --version` executed straight from the unpacked tree |
| `релиз` | `ubuntu-latest` | on a `v*` tag: `.pkg.tar.zst` and `SHA256SUMS.pkg` in the GitHub Release |

Release mechanics:

- the tag has to match `v<version>` from `Cargo.toml` (`v0.3.0` right now);
  `workflow_dispatch` takes an optional `version` input for a manual check;
- no secrets are needed — the AUR upload stays manual;
- the release job uses `concurrency: release-<ref>` with `cancel-in-progress:
  false`. The `GitHub Release` job in `rs-ci.yml` still has no concurrency group,
  so a single tag can start both release steps at once; adding the same group
  there is tracked in `TODO.md`;
- checksum files are kept apart: `rs-ci.yml` publishes `SHA256SUMS` for the
  `tar.gz` archives, `rs-packaging.yml` publishes `SHA256SUMS.pkg` for the Arch
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
| `UMBRAWG_SOCKET_BUFFER` | `8388608` (8 МиБ) | Размер `SO_RCVBUF` и `SO_SNDBUF` каждого UDP-сокета в байтах: от `217088` (212 КиБ) до `67108864` (64 МиБ). Некорректное значение — ошибка при старте. Если ядро урезало буфер (`net.core.rmem_max`/`wmem_max`), демон пишет предупреждение с фактическим размером. |
| `UMBRAWG_UNDERLAY_MTU` | `1500` | MTU сети под туннелем (underlay) в байтах, от `576` до `65535`. Из него считается максимальный GSO-сегмент: `MTU − 28` (IPv4+UDP). На `9000` обфусцированные сегменты `1420 + 32 + S4` уходят одним GSO-пакетом, на `1500` сегменты крупнее `1472` GSO не используют и отправляются обычными датаграммами с IP-фрагментацией. Если `TUN MTU + 32 + S4` больше этого MTU, демон один раз предупреждает при старте и при применении конфигурации. |
| `UMBRAWG_GSO_SEGMENTS` | `64` | Потолок сегментов в одной GSO-супер-датаграмме, от `1` до `64`. Больше сегментов — меньше syscall и выше скорость на jumbo-underlay, но одна потеря сегмента обходится дороже: хвост супер-датаграммы отбрасывается вместе с ним. |
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
> однопоточного rust на 6.2–16.2% на одном пире в 5 из 8 ячеек матрицы final5
> (в 3c c=10 он быстрее на +8.0%/+9.8%, в 3c c=1 obf=1 — на +2.4%) и на
> 11.2%/11.7% в multi-peer (obf=0/1); см. раздел «Производительность» и
> [tools/docs/RESULTS.md](tools/docs/RESULTS.md). Цели +30%/+60% не достигнуты,
> но 3c c=10 — уже аргумент включать его на многоядерных хабах.
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

`DisableCookies` — осознанный компромисс, а не «выключение защиты от флуда»:
без cookie любой пакет инициации с валидным MAC1 (а MAC1 считается по
публичному ключу, который есть у всех) доходит до дорогой криптографии Noise.
Детектор `under_load` в этом режиме не может отсеять подделанные адреса
отправителей, поэтому усилитель трафика на 6 vCPU будет стоить примерно
столько же циклов, сколько принесли пакеты: ограничение — 20 инициаций в
секунду на адрес отправителя, а при подмене адресов оно не работает. Не
включайте `DisableCookies` на публичном endpoint, если не ограничили поток
инициаций на границе сети (firewall/rate limit у провайдера); для приватных
линков с известными адресами пиров режим допустим.

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

Финальные замеры (final5, сервер 6 vCPU, MTU 9000, 3 повтора) — полная матрица
и методика в [tools/docs/RESULTS.md](tools/docs/RESULTS.md). К final4 фиксы
per-byte Poly1305, буферов сокетов и флуд-детектора дали +18.4…+27.5% на всех
TCP-ячейках и +30…+40% в multi-peer; GSO-фикс обфускации (final3→final4) до
этого ускорил `obf=1` в 1.8–2.8 раза.

Ключевые цифры (TCP, Мбит/с, медиана 3 повторов):

| Сценарий | kernel | rust | go |
|---|---|---|---|
| 1c, c=1, obf=0 | 2316 | 1947 | 2126 |
| 1c, c=1, obf=1 | 2224 | **1719** | 1906 |
| 1c, c=10, obf=0 | 1803 | **1825** | 1251 |
| 1c, c=10, obf=1 | 1758 | 1691 | 1208 |
| 3c, c=1, obf=0 | 2352 | 2602 | 3720 |
| 3c, c=1, obf=1 | 2267 | 2042 | 2705 |
| 3c, c=10, obf=0 | 1800 | **2673** | 4534 |
| 3c, c=10, obf=1 | 1640 | **2591** | 3982 |
| 4 пира, 3c, c=10, obf=0 | 5187 | **5477** | 4498 |
| 4 пира, 3c, c=10, obf=1 | 4443 | **4971** | 3499 |

UDP: `rust` держит линию 1G во всех ячейках (999.2–999.9, потери ≤0.09%),
кроме 1c c=10 obf=1 (986.5, 1.3%); `obf=0` не регрессировал.

Где обгоняем: на 3c c=10 rust (2673) обгоняет kernel (1800) и amneziawg (1613)
на +48.5%/+65.7% при obf=0; при obf=1 — 2591 против 1640 и 1515
(+58.0%/+71.0%). На 1c c=10 obf=0 rust впервые выше ядра (1825 против 1803).
В multi-peer rust — лидер: 5477/4971 против 5187/4443 у ядра (+5.6%/+11.9%)
и 4498/3499 у go (+21.8%/+42.0%), при 8.0/4.8 тыс. ретрансмитов против
19.8/16.8 тыс. у ядра.
Где отстаём: 1c c=1 — 1947/1719 против 2316/2224 у ядра (16–23% ниже) и
против 2126/1906 у go; 3c c=1 против go — 25–30% ниже; 3c c=10 против go —
41.0%/34.9% ниже.
`obf=1` больше не проваливается: разрыв с `obf=0` — 7–12% на 1c и 3–22% на 3c.

### GSO и MTU подложки

GSO-супер-датаграмма — один `sendmsg` с `UDP_SEGMENT`; ядро режет её на
сегменты, каждый из которых становится отдельным IP-пакетом. Ядро сегментирует
по `gso_size`, но не фрагментирует сегменты, поэтому `gso_size` обязан
помещаться в MTU underlay: кадр `gso_size + 28` байт не должен превышать MTU.
Демон берёт `gso_size ≤ UMBRAWG_UNDERLAY_MTU − 28`; всё крупнее уходит обычной
датаграммой, и фрагментацию выполняет IP-стек.

Пример расчёта для TUN MTU `1420` и профиля с `S4 = 60`: пакет данных
занимает `1420 + 32 + 60 = 1512` байт UDP payload. На underlay `1500` бюджет
IPv4-payload равен `1500 − 28 = 1472`, поэтому `1512 > 1472`: такой сегмент не
GSO, демон пишет предупреждение
`TUN MTU 1420 + 92 bytes ... exceeds the 1472-byte IPv4 payload budget` и
рекомендует `TUN MTU 1380`; трафик идёт обычными датаграммами с
IP-фрагментацией (как до GSO-фикса): кадры не превышают MTU, но пропускная
способность ниже, чем с GSO. На underlay `9000` (`1512 ≤ 8972`) тот же профиль
использует GSO. Дефолт `1500` выбран безопасным: jumbo-underlay включается
явно через `UMBRAWG_UNDERLAY_MTU`:

```sh
UMBRAWG_UNDERLAY_MTU=9000 UMBRAWG_GSO_SEGMENTS=64 umbrawg uwg0
```

Замер final5 (rust, obf=1, `S4=60`, 3 повтора) показывает цену такого профиля
на узком underlay: TCP 1c — 697 против 1700 Мбит/с, 3c — 1082/1033 против
2161/2724 (−50…−62%); UDP 1c — 640 Мбит/с с 36–38% потерь (перегруз приёма
при 1G), 3c — 967–977 с 2.3–3.3%. По 48 pcap × 60 000 кадров превышения MTU
нет: max frame 1514, кадров >1514 и >1518 — 0. Деградация целиком от
IP-фрагментации: 27.9 млн фрагментов за 24 прогона. Для underlay 1500 и
`S4=60` держите `TUN MTU ≤ 1380` — тогда `1380 + 92 = 1472` влезает в бюджет
и GSO снова работает.

`UMBRAWG_GSO_SEGMENTS` ограничивает размер супер-датаграммы: при потере
датаграммы в сети теряется её хвост, поэтому потолок нужен как компромисс между
числом syscall и ценой потери. Замеры на underlay 9000 (S4=60, obf=1, 3 повтора)
не показали систематического выигрыша 32/64 сегментов относительно прежних 44
(разница в пределах шума ±5%), а 8 сегментов теряли 8% на 3c c=1. По умолчанию
32: паритет со старым поведением при меньшем худшем случае потери одной
супер-датаграммы; 16 (прежний кандидат) на 0.5–4% ниже 44 в 3 из 4 ячеек.

Параллельный приём (`UMBRAWG_PARALLEL_RX=1`) — экспериментальный: на одном пире
он медленнее обычного rust на 6.2–16.2% в 5 из 8 ячеек матрицы final5
(в 3c c=10 быстрее на +8.0%/+9.8%, в 3c c=1 obf=1 — на +2.4%) и на
11.2%/11.7% в multi-peer; цели +30%/+60% не достигнуты. Рекомендуется
оставлять выключенным по умолчанию; включать для многоядерных хабов (3c c=10)
и замеров. Подробнее — раздел «Параллельный приём» и
[tools/docs/RESULTS.md](tools/docs/RESULTS.md).

Ядро (`kernel-umbrawg`) на c=1 достигло +33.5% (1c obf=0), +33.9% (1c obf=1),
+32.2%/+31.6% (3c) к `kernel-amneziawg`.

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

Прогон final5 (сервер 6 vCPU, veth, `sched=peer`, 32 MiB, профиль `S4=60`),
underlay MTU 9000 (по 4 повтора на ячейку):

| Прогон | parallel | obf | iperf3 TCP | Ретрансмиты | iperf3 UDP | Дропы |
|---|---|---|---|---|---|---|
| `obf0-par0` | 0 | 0 | 2641–2834 Мбит/с | 0 | 200 Мбит/с, 0% | n/a (нет stats) |
| `obf0-par1` | 1 | 0 | 2607–2864 Мбит/с | 0–1 | 200 Мбит/с, 0% | A:0 B:0 |
| `obf1-par0` | 0 | 1 | 2586–2657 Мбит/с | 0–1 | 200 Мбит/с, 0% | n/a (нет stats) |
| `obf1-par1` | 1 | 1 | 2574–2809 Мбит/с | 0 | 200 Мбит/с, 0% | `prepared=9` (specials) |

Underlay MTU 1500 (там же):

| Прогон | parallel | obf | iperf3 TCP | Ретрансмиты | Дропы |
|---|---|---|---|---|---|
| `obf0-par0` | 0 | 0 | 2804 Мбит/с | 0 | n/a |
| `obf0-par1` | 1 | 0 | 2840 Мбит/с | 0 | A:0 B:0 |
| `obf1-par0` | 0 | 1 | 1020–1214 Мбит/с | 0–1 | n/a |
| `obf1-par1` | 1 | 1 | 1092–1145 Мбит/с | 0–16 | A:`queue=16248…21158` (43%) |

Во всех прогонах на обоих underlay ping без потерь, sha256 файла 32 МиБ
совпал, UDP 0%.
Ретрансмиты `obf=1` упали с 7169–8004 (final4) до 0–16 — эффект
per-byte/sockbuf-фиксов. На 1500 + `S4=60` + parallel тест валит порог
`queue ≤ 1%`: пакет `1420+92=1512 > 1472` уходит без GSO с IP-фрагментацией и
переполняет очередь ACK-ами, хотя данные целы (нет дропов
`detect/size/replay/tun/tx`).

Привязка по пиру (`peer`, по умолчанию) сохраняет порядок пакетов: ретрансмиты
`obf=0` нулевые в обоих режимах, а на 1500 + obf=1 не превышают 16. `queue`
остаётся для замеров: скорость выше, но TCP видит перестановку и массово
ретранслирует.

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

### Буферы UDP-сокета

Каждый сокет запрашивает `SO_RCVBUF` и `SO_SNDBUF` размером
`UMBRAWG_SOCKET_BUFFER` (по умолчанию 4 МиБ, допустимо 212 КиБ..64 МиБ,
значение в байтах). Большой буфер нужен, чтобы входящий всплеск трафика не
терялся до обработки: с дефолтными `net.core.rmem_max=212992` ядро молча
урезает запрос примерно до 208 КиБ (212 992 Б), и `obf=1` деградирует под
нагрузкой.

После установки демон читает фактический размер через `getsockopt` (Linux
возвращает удвоенное значение, поэтому фактический размер — половина
прочитанного) и сравнивает с запрошенным с допуском 4 КиБ. Если буфер урезан,
в лог один раз при создании сокета пишется предупреждение с фактическим и
запрошенным размером и советом поднять лимит:

```text
SO_RCVBUF was clamped by the kernel: effective 212992 bytes,
requested 4194304 bytes; raise net.core.rmem_max or lower UMBRAWG_SOCKET_BUFFER
```

Поднять лимит на хосте (systemd-sysctl или `sysctl.conf`):

```sh
sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216
```

Либо уменьшить `UMBRAWG_SOCKET_BUFFER` до значения, которое ядро принимает без
урезания. Некорректное значение переменной (не число, вне диапазона) — ошибка
при старте, а не молчаливый откат к умолчанию.

## Производительность на стенде

Стенд 3c/10 (veth MTU 9000, TUN 1420), `ring`, `GSO=64`, буфер 8 МиБ:

| Настройки | RPS | obf0 | obf1 |
|---|---|---:|---:|
| `rust`, 4 порта (включено) | `0x34` | **5931** | **5760** |
| `rust`, 8 портов | `0x34` | 5732 | 5675 |
| `rust-par`, 4 порта | `0x34` | 5968 | 5645 |
| `rust`, без доп. портов | `0x30` | 5158 | 5203 |
| `rust-par`, без доп. портов | `0x30` | 5886 | 5653 |
| `go` (amneziawg-go) | `0x34` | 5030 | 4611 |
| `go` (amneziawg-go) | `0x30` | 4669 | 4206 |

`GSO_SEGMENTS=64` и буфер 8 МиБ — дефолты; `extra_ports=0` по умолчанию.
Дополнительные
порты дают лучший результат в одном рабочем потоке и делают параллельный
приём необязательным: несколько внешних 4-tuple раскладывают softirq пира
по CPU через RPS. Параллельный приём остаётся opt-in для профилей, где
крипто-нагрузка важнее сетевой.

Дополнительные порты (4 по умолчанию) открываются на каждого воркера,
поэтому память растёт как `воркеры × (порты + 1) × 2 × буфер`. При
3 воркерах, 5 портах и буфере 8 МиБ это заметный объём (ядро учитывает
`SO_RCVBUF` и `SO_SNDBUF` с двойным запасом); `ExtraPorts = 0` возвращает
один сокет на воркера.

## UAPI: `extra_ports`

Ключ `extra_ports=N` в `set=1` задаёт число дополнительных внешних
UDP-портов устройства (0…8, по умолчанию 0 — выключено). Значение
всегда возвращается в `get=1`. Дополнительные сокеты эфемерные:
базовый слушает `listen_port`, остальные выбирает ядро; отправка идёт
по кругу, приём — со всех. Настройка меняется на ходу: набор сокетов
пересоздаётся на следующей итерации воркера/RX-потока.

Включайте дополнительные порты только в сетях без port-restricted NAT:
ответы уходят с другого source-порта, и такой NAT их отбрасывает. В
обычном режиме каждый воркер открывает свой набор, поэтому сокетов
`воркеры × (N + 1)`; в `UMBRAWG_PARALLEL_RX=1` набор один на устройство.

## UAPI: `advanced_security`

Демон принимает ключ `advanced_security` в `set=1` для пира (`on`/`off`,
`true`/`false`, `1`/`0`) и возвращает `advanced_security=1|0` в `get=1`, если
значение было задано. Поле информационное: userspace-демон не реализует
advanced security и не меняет обработку пакетов или таймеры. Для реального
включения нужен модуль ядра. Если значение не задавалось, строка в `get=1` не
выводится — это сохраняет совместимость с Go-клиентами и `uwg`.

## UAPI: `cipher`

Демон принимает ключ `cipher` в `set=1` для пира и возвращает его в `get=1`,
если значение отличается от значения по умолчанию:

- `chacha20-poly1305` (по умолчанию) — ChaCha20-Poly1305, как в WireGuard;
- `aes-256-gcm` — AES-256-GCM с тем же 96-битным nonce и 16-байтным тегом.

Шифр выбирается для transport-пакетов конкретного пира. Handshake, cookie,
обфускация и формат провода не меняются, поэтому старые конфигурации и клиенты
продолжают работать по ChaCha. Один сервер может одновременно обслуживать
пиров с ChaCha20-Poly1305 и AES-256-GCM. Шифр задаётся на обеих сторонах: при
несовпадении handshake проходит, но transport-пакеты отбрасываются.

В конфигурации `uwg`/`uwg-quick` используется ключ `Cipher` в секции `[Peer]`:

```ini
[Peer]
PublicKey = ...
Cipher = aes-256-gcm
```

Эквивалент через CLI: `uwg set uwg0 peer <base64-ключ> cipher aes-256-gcm`.

Смена `Cipher` применяется к следующей сессии: уже установленный keypair
продолжает работать со старым шифром до rekey или перезапуска интерфейса.
Шифр должен совпадать на обеих сторонах, иначе handshake проходит, а
transport-пакеты отбрасываются.

Transport-AEAD в демоне по умолчанию считается через `ring` (features
`aes-ring` и `ring-chacha`, включены в `umbrawg`): на стенде AES дал
~6.0 Гбит/с против ~4.1 у RustCrypto, ChaCha — 5.26/5.01 Гбит/с
(obf0/obf1) против 4.67/4.21 у `go`. `ring` использует AES-NI/VAES,
AVX2 ChaCha и ARMv8 Crypto Extensions и требует C-ассемблер при сборке.
Сборка без него — `cargo build -p umbrawg --no-default-features` —
оставляет RustCrypto для обоих шифров.

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
[RELEASE.md](https://github.com/ivlev-dev/umbrawg/blob/master/umbrawg-tools/RELEASE.md).

## Status

The Go implementation that this workspace replaces remains in the git history
(`master`) as a behavioural reference. Obfuscation (H1-H4, S1-S4, Jc/Jmin/Jmax,
I1-I5, header protection, content padding, random trailers) is implemented in
`umbrawg-proto` and exercised by tests in `umbrawg-device`.
