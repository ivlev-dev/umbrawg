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
| `UMBRAWG_RX_STATS` | выключено (`0`/не задано) | `1` включает вывод счётчиков приёма каждые 5 секунд (пакеты, батчи, сегменты, GRO/GSO, дропы, пробуждения). |
| `UMBRAWG_LOG_LEVEL` | `info` | Уровень логирования (`trace`, `debug`, `info`, `warn`, `error`). |
| `UMBRAWG_RUNTIME_DIR` | `/var/run/umbrawg` | Каталог unix-сокетов UAPI (`<iface>.sock`). При задании копируется в `UWG_RUNTIME_DIR` для совместимости с `umbrawg-tools`. |
| `UWG_RUNTIME_DIR` | `/var/run/umbrawg` | То же, что `UMBRAWG_RUNTIME_DIR`, читается сервером UAPI напрямую (совместимость с `uwg`/`uwg-quick`). |

## Параллельный приём

Включается переменной `UMBRAWG_PARALLEL_RX=1` (по умолчанию выключен). Опционально:
`UMBRAWG_RX_WORKERS=N`, `UMBRAWG_RX_SCHED=peer|queue`, `UMBRAWG_RX_STATS=1`.

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
- управляющие пакеты (рукопожатие, cookie) обрабатываются потоком приёма;
- переполнение: если очередь выбранного пиром воркера заполнена, дейтаграмма
  дропается со счётчиком `drops(queue)`, а не перекидывается на другой воркер —
  иначе порядок сломался бы. Пир на другом воркере от этого не страдает:
  у каждого пира своя привязка.

Режим `UMBRAWG_RX_SCHED=queue` (для замеров) раскладывает задания по наименее
загруженной очереди. Он даёт большую суммарную скорость на одном потоке, но
переставляет пакеты между воркерами и вызывает ретрансмиты TCP; по умолчанию
не используется.

Ограничения и компромиссы:

- порядок пакетов между разными пирами не гарантируется (каждый пир — свой воркер);
- пропускная способность одного пира ограничена одним воркером, то есть близка
  к однопоточному режиму; выигрыш даёт сумма пиров;
- память около 16 МиБ на воркера (256 буферов по 64 КиБ): глубокая очередь нужна,
  чтобы приём не терял дейтаграммы на всплесках при привязке по пиру;
- управляющие пакеты обрабатываются в RX-потоке, флуд инициаций может
  задерживать обработку данных;
- режим opt-in; перевод в default-on требует soak-тестирования на реальном
  NIC и ARM.

Счётчики при `UMBRAWG_RX_STATS=1` выводятся в лог раз в 5 секунд: режим
(`sched`), дейтаграммы, сегменты, GRO-разбиения, управляющие пакеты,
`mixed_peers`, дропы (классификация, подготовка, переполнение очереди, размер,
TUN, передача), пробуждения воркеров.

Отключить: не задавать `UMBRAWG_PARALLEL_RX` или установить значение, отличное
от `1`/`true`/`yes`/`on` (по умолчанию однопоточный режим, который не деградирует
на одном соединении).

## Data-plane E2E

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

Пример прогона на 12-ядерном хосте (veth, без реального NIC):

| Прогон | parallel | sched | obf | iperf3 TCP | Ретрансмиты | iperf3 UDP | Дропы |
|---|---|---|---|---|---|---|---|
| `obf1-par0` | 0 | — | 1 | 1280 Мбит/с | 24 845 | 200 Мбит/с, 0/36561 | n/a (нет stats) |
| `obf1-par1` | 1 | `peer` | 1 | 1216 Мбит/с | 27 526 | 200 Мбит/с, 0/36555 | `prepared=9` (specials) |
| `obf1-par1` | 1 | `queue` | 1 | 1670 Мбит/с | 120 608 | 200 Мбит/с, 0/36555 | 0 |
| `obf0-par0` | 0 | — | 0 | 2672 Мбит/с | 0 | 200 Мбит/с, 0/36568 | n/a (нет stats) |
| `obf0-par1` | 1 | `peer` | 0 | 2780 Мбит/с | 0 | 200 Мбит/с, 0/36563 | 0 |
| `obf0-par1` | 1 | `queue` | 0 | 6003 Мбит/с | 13 516 | 200 Мбит/с, 0/36563 | 0 |

Во всех прогонах ping без потерь, sha256 файла 32 МиБ совпал.

Привязка по пиру (`peer`, по умолчанию) убирает перестановку: на одном пире
скорость совпадает с однопоточным режимом, ретрансмитов нет (`obf=0`).
`queue` остаётся для замеров: суммарная скорость выше, но TCP видит перестановку
и массово ретранслирует. При `obf=1` ретрансмиты есть и в однопоточном режиме
(путь обфускации в veth-стенде упирается в CPU), поэтому `peer` сравнивается
с `par0`, а не с нулём.

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
