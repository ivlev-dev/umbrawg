# TODO — userspace UmbraWG (Rust)

## Текущее состояние

- Ветка `master` (после слияния `feature/rust-rewrite`), всё запушено.
- Go-реализация удалена из рабочего дерева; она осталась в истории git (`master` до слияния)
  и в `/opt/baseline/orig-go` на сервере как поведенческий эталон.
- Работает end-to-end: TUN ↔ UDP, Noise IK, обфускация 3.1, UAPI-сервер.
- Проверен interop с модулем ядра `umbrawg` в обе стороны, с обфускацией и без.

### Структура

| Крейт | Назначение |
|---|---|
| `umbrawg-crypto` | BLAKE2s, ChaCha20-Poly1305, X25519, TAI64N |
| `umbrawg-proto` | сообщения, кадрирование, параметры и преобразования обфускации |
| `umbrawg-noise` | Noise IK, cookie |
| `umbrawg-device` | Device/Peer, allowed-ips, replay, ratelimiter, таймеры, UAPI-адаптер |
| `umbrawg-transport` | UDP-сокеты, `recvmmsg`/`sendmmsg`, GSO (`UDP_SEGMENT`), GRO (`UDP_GRO`) |
| `umbrawg-tun` | TUN, multi-queue, virtio-net offload |
| `umbrawg-uapi` | UAPI-сервер `/var/run/umbrawg/<iface>.sock` |
| `umbrawg-bench` | criterion-микробенчмарки горячего пути |
| `umbrawg` | демон |

## Сборка, тесты, запуск

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p umbrawg
sudo ./target/release/umbrawg --foreground uwg0
```

Конфигурация — через `uwg` из `umbrawg-tools` (тот же CLI, что и для модуля ядра).

## Измерено (final3, 6 vCPU, MTU 9000, 3 повтора)

Ключевые цифры (TCP, Мбит/с, медиана 3 повторов); полная матрица и методика —
в `tools/docs/RESULTS.md`.

| Сценарий | kernel | rust | go |
|---|---|---|---|
| 1c, c=1, obf=0 | 2373 | 1529 | 2069 |
| 1c, c=1, obf=1 | 2267 | 663 | 2026 |
| 3c, c=1, obf=0 | 2461 | 2044 | 3725 |
| 3c, c=1, obf=1 | 2212 | 877 | 3148 |
| 3c, c=10, obf=0 | 1914 | 2328 | 5263 |
| 3c, c=10, obf=1 | 1770 | 828 | — |
| 1c, c=10, obf=0 | — | 1358 | 1155 |
| 4 пира, 3c, c=10 | 4951 | 3997 | 4971 |

rust-par: 4 пира 3576 Мбит/с; во всех 8 ячейках матрицы медленнее обычного rust
на 1–16.6%. Режим остаётся opt-in/экспериментальным. Цели +30%/+60% для rust-par
не достигнуты; ядро достигло +30% на c=1. Fast-path дал +12.6…+103%.

## Известные проблемы

- С обфускацией Go-эталон деградирует до ~4 Мбит/с — сравнение с ним требует проверки
  конфигурации эталона (вероятно, раздувание trailers), иначе цель «+30%» занижена.
- Поддержка только IPv4-сокетов (`AddressFamily::Ipv4`); IPv6-подложка не подключена.
- `RandomTrailers`/padding реализованы, но влияние на MTU/фрагментацию не отлажено.
- Android/iOS не портированы (в задаче пока не нужны).
- Первый handshake со стороны ядра теряется из-за гонки биндинга порта (см. kernel TODO).

## Что делать дальше (по приоритету)

1. Профилирование: `perf record -g` на демоне, flamegraph; счётчики syscall через `strace -c`.
2. Оптимизация до +30% (1 ядро) и +60% (3 ядра) относительно Go-эталона — для rust-par
   не достигнута (медленнее rust на 1–16.6% на одном пире); ядро достигло +30% на c=1.
   Остаются обфускация на 1c (obf=1), single-core (1c) и реальный NIC.
3. IPv6-подложка и dual-stack сокеты.
4. Оптимизация под ARM64/ARMv7: NEON-путь для ChaCha20, сборка `aarch64-unknown-linux-gnu`,
   `armv7-unknown-linux-gnueabihf`.
5. Interop-тесты как cargo-тесты с автоскипом без root (сейчас — shell-скрипты в tools/bench).
6. Перевод параллельного приёма в default-on — только после soak-тестирования на реальном
   NIC и ARM (сейчас opt-in/экспериментальный).

## Пакетирование и релиз

- `.github/workflows/packaging.yml` собирает Arch-пакет демона и не дублирует
  `tar.gz` из `ci.yml`:
  - job `arch` (`archlinux:latest`) — `makepkg -f --noconfirm --nodeps` для
    `contrib/arch/umbrawg-daemon-git` (вместе с `check()` из PKGBUILD), затем
    проверка содержимого: `/usr/bin/umbrawg`, `umbrawg@.service`,
    `tmpfiles.d/umbrawg.conf` (`d /run/umbrawg 0700 root root -`), `/etc/umbrawg`
    с правами `0700`, и запуск `umbrawg --version` из распакованного пакета;
  - job `релиз` на тег `v*` — `.pkg.tar.zst` + `SHA256SUMS.pkg` в GitHub Release.
- Тег должен совпадать с версией workspace (`v0.1.0`); секреты не нужны,
  публикация в AUR остаётся ручной.
- Контрольные суммы разделены: `ci.yml` публикует `SHA256SUMS` для `tar.gz`,
  `packaging.yml` — `SHA256SUMS.pkg` для Arch-пакета, чтобы не перезаписывать
  ассет друг друга.
- В `ci.yml` у job `GitHub Release` нет `concurrency`-группы: при теге оба
  релизных job могут стартовать одновременно. Добавить туда
  `group: release-${{ github.ref }}` — отдельная задача.
- Стабильный `contrib/arch/umbrawg-daemon` в CI не собирается: в `sha256sums`
  заглушка `TODO_UPDPKGSUMS_AFTER_FIRST_TAG`, после тега нужны `updpkgsums` и
  `makepkg --printsrcinfo > .SRCINFO`.
- Workflow проверен в Docker (makepkg, содержимое пакета, `--version`), в GitHub
  Actions ещё не запускался.

## Соглашения

- Байты на проводе и UAPI-формат совместимы с модулем ядра и Go-эталоном.
- Горячий путь без аллокаций и без `format!`/логов выше `debug`.
- Коммиты на русском, Conventional Commits; ветки `feature/*`, слияние в `master`.
