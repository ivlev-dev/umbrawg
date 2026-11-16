# Changelog

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версии соответствуют [SemVer](https://semver.org/lang/ru/).

## [0.1.0] — 2026-11-17

Userspace-демон UmbraWG на Rust: протокол WireGuard-совместим (Noise IK) с
обфускацией UmbraWG 3.1, байтовая совместимость с модулем ядра `umbrawg`.

### Добавлено

- `umbrawg-crypto`: BLAKE2s, ChaCha20-Poly1305, X25519, TAI64N, CSPRNG.
- `umbrawg-proto`: сообщения, кадрирование, обфускация H1-H4, S1-S4,
  Jc/Jmin/Jmax, I1-I5, header protection, content padding, random trailers.
- `umbrawg-noise`: рукопожатие Noise IK, cookie, вывод ключей.
- `umbrawg-device`: Device/Peer, allowed-ips, replay-фильтр, ratelimiter,
  таймеры, очередь исходящих пакетов.
- `umbrawg-transport`: UDP-сокеты, `recvmmsg`/`sendmmsg`, GSO (`UDP_SEGMENT`),
  GRO (`UDP_GRO`), sticky sockets (`IP_PKTINFO`/`IPV6_PKTINFO`), `SO_MARK`,
  `SO_BINDTODEVICE`, path MTU discovery.
- `umbrawg-tun`: TUN multi-queue, virtio-net header, GSO/GRO offload,
  управление MTU, дескрипторы для `poll(2)`.
- `umbrawg-uapi`: парсер/сериализатор UAPI, unix-сокет
  `/var/run/umbrawg/<iface>.sock`, авторизация по `SO_PEERCRED`.
  Новый публичный метод `UapiListener::spawn_with_authorizer`; `run` и `spawn`
  сохраняют политику «только root».
  Ключ пира `advanced_security` принимается в `set=1` и возвращается в `get=1`,
  если был задан; значение хранится, но не влияет на поведение демона.
- `umbrawg`: демон с запуском очередей, обработкой сигналов, `--foreground`,
  `--version`, `--help`, переменными окружения `UMBRAWG_THREADS`,
  `UMBRAWG_PARALLEL_RX`, `UMBRAWG_RX_WORKERS`, `UMBRAWG_RX_STATS`,
  `UMBRAWG_LOG_LEVEL`, `UMBRAWG_RUNTIME_DIR`.
- Параллельный приём: RX-поток с `recvmmsg`, SPSC-очереди заданий и
  крипто-воркеры с `AtomicReplayFilter`.
- `umbrawg-bench`: criterion-микробенчмарки горячего пути.
- 406 тестов workspace, включая паритетные тест-векторы и UAPI end-to-end.

### CI и сборка

- `.github/workflows/ci.yml`:
  - `test stable` — `fmt --check`, `clippy -D warnings`, тесты workspace,
    `cargo doc` с `-D warnings`;
  - `msrv 1.88` — сборка и компиляция тестов на минимальной версии тулчейна;
  - `build <target>` — release-сборки `x86_64-unknown-linux-gnu`,
    `aarch64-unknown-linux-gnu`, `armv7-unknown-linux-gnueabihf` через
    кросс-линкеры `gcc-aarch64-linux-gnu`/`gcc-arm-linux-gnueabihf` и
    `libc6-dev-*-cross`, проверка архитектуры через `file`/`readelf`,
    запуск бинарника и unit-тестов под `qemu-user-static`, упаковка `tar.gz`;
  - `GitHub Release` — на тег `v*` публикует архивы и `SHA256SUMS`.
- В манифесте объявлена минимальная версия Rust — `rust-version = "1.88"`.
- Артефакт: `umbrawg-<version>-<target>.tar.gz` с `usr/bin/umbrawg`,
  документацией в `usr/share/doc/umbrawg/` и `systemd/*.service`, если каталог
  есть в репозитории (юнит `umbrawg@.service` поставляется `umbrawg-tools`).

### Исправлено

- `Dockerfile` собирался на `rust:1.85-bookworm`, но workspace использует
  `slice::as_chunks` (Rust 1.88): образ обновлён до `rust:1.88-bookworm`.
- UAPI-тесты падали под непривилегированным пользователем (`errno=-13`), потому
  что использовали root-only `UapiListener::spawn`; теперь они поднимают сервер
  через `spawn_with_authorizer` с авторизацией по текущему uid. Это делает
  `cargo test --workspace` пригодным для запуска на CI-раннере без root.
- `parallel::tests::waiting_worker_wakes_up_and_exits` был нестабильным: ожидание
  свободного буфера ограничивалось фиксированным числом спин-итераций. Теперь
  ожидание ограничено дедлайном 10 с с `yield_now`, тест не зависит от загрузки
  машины.
