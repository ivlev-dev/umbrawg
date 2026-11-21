# TODO — userspace UmbraWG (Rust)

## Текущее состояние

- Ветка `master` (после слияния `feature/rust-rewrite`), всё запушено.
- Версия workspace — `0.4.1` (2026-11-21).
- Go-реализация удалена из рабочего дерева; она осталась в истории git (`master` до слияния)
  как поведенческий эталон.
- Работает end-to-end: TUN ↔ UDP, Noise IK, обфускация 3.1, UAPI-сервер.
- BBRv3/FEC: CAPS/ACK/FEC_SHARD, adaptive `2:1`, fixed `1..8 / 1..2`,
  ACK-clocked `cwnd`-гейт после loss-cut, отзыв CAPS, статистика
  `bbr_stats`/`fec_stats`, runtime `underlay_mtu`.
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

## Измерено (final5, 6 vCPU, MTU 9000, 3 повтора)

Ключевые цифры (TCP, Мбит/с, медиана 3 повторов); полная матрица и методика —
в `tools/docs/RESULTS.md`.

| Сценарий | kernel | rust | go |
|---|---|---|---|
| 1c, c=1, obf=0 | 2316 | 1947 | 2126 |
| 1c, c=1, obf=1 | 2224 | 1719 | 1906 |
| 1c, c=10, obf=0 | 1803 | 1825 | 1251 |
| 1c, c=10, obf=1 | 1758 | 1691 | 1208 |
| 3c, c=1, obf=0 | 2352 | 2602 | 3720 |
| 3c, c=1, obf=1 | 2267 | 2042 | 2705 |
| 3c, c=10, obf=0 | 1800 | 2673 | 4534 |
| 3c, c=10, obf=1 | 1640 | 2591 | 3982 |
| 4 пира, 3c, c=10, obf=0 | 5187 | 5477 | 4498 |
| 4 пира, 3c, c=10, obf=1 | 4443 | 4971 | 3499 |

UDP: `rust` держит линию 1G во всех ячейках (999.2–999.9, потери ≤0.09%),
кроме 1c c=10 obf=1 (986.5, 1.3%). `rust-par` на одном пире медленнее
обычного rust на 6.2–16.2% в 5 из 8 ячеек, но быстрее в 3c c=10
(+8.0%/+9.8%); режим остаётся opt-in.

### Матрица 2026-11-21 (veth, 6 vCPU)

Два независимых прохода v2/v3 против `amneziawg` 3.1.20261113-02 и
`amneziawg-go`; Go-форк удалён и в матрице не участвует. TCP, медиана двух
проходов, Гбит/с:

| Реализация | 0% | 2% | 5% | 10% |
|---|---|---|---|---|
| `awg-go` | 6.150 | 0.250 | 0.036 | 0.005 |
| `awg-kernel` | 1.880 | 0.320 | 0.034 | 0.003 |
| `uwg-rust off` | 5.460 | 0.276 | 0.022 | 0.006 |
| `rust BBR` | 4.274 | 0.262 | 0.030 | 0.003 |
| `rust FEC 2:1` | 1.399 | 0.646 | 0.112 | 0.024 |

- Чистый канал: Rust 5.460 против 6.150 у `awg-go` (−11.2%) и 3.150 у
  `uwg-kernel` (+73.3%).
- FEC `2:1`: ×2.34 на 2%, ×5.19 на 5%, ×4.27 на 10% к тому же стеку без FEC;
  цена — −72…−77% на чистом канале и RTT 3.6–4.3 мс против 0.30–0.34 мс.
- BBR: −21.7% на чистом канале, на потерях без FEC выигрыша нет, с FEC —
  ниже FEC на 0–2% потерь. Держать `off` по умолчанию, с FEC не включать.
- Аномалии: FEC на 0% дал 1.257 и 1.540 Гбит/с в разных проходах; на чистом
  канале 0.08–0.1% UDP-потерь при 400 Мбит/с.

Полные таблицы, UDP, RTT и воспроизводимость —
[`../docs/BENCHMARKS-2026-11-21.md`](../docs/BENCHMARKS-2026-11-21.md).

## Известные проблемы

- Поддержка только IPv4-сокетов (`AddressFamily::Ipv4`); IPv6-подложка не
  подключена. Значение `underlay_mtu` меняется на ходу, но перезапуск
  процесса всё равно берёт стартовое значение из env.
- Android/iOS не портированы (в задаче пока не нужны).
- Первый handshake со стороны ядра теряется из-за гонки биндинга порта (см. kernel TODO).
- FEC стоит TCP: в 0.4.1 на 9k защищённый TCP — 1.18–1.21 Гбит/с (kernel)
  и 1.26–1.54 (rust) против 3.15/5.46 без FEC. Исторические 930–1130
  против ~2.7 относятся к другому прогону; на 8:2 — 690–1140, в 0.4.1 не
  перемерялось. Блок собирается дольше, чем TCP входит в recovery.
- На чистом канале Rust теряет 0.08–0.1% UDP при 400 Мбит/с; без FEC потери
  должны повторять `netem` (±0.4 п.п.). Причина не установлена, см. матрицу
  2026-11-21.
- `rust FEC 2:1` на 0% дал 1.257 и 1.540 Гбит/с в разных проходах (+22.5%) —
  повышенный межпроходный разброс, нужен третий проход.
- Потолок шарда 1900 байт и короткий ACK-bitmap (64 пакета) остаются
  ограничениями; reorder с задержкой больше 1 с adaptive считает потерей.

## Что делать дальше (по приоритету)

1. Профилирование: `perf record -g` на демоне, flamegraph; счётчики syscall через `strace -c`.
2. IPv6-подложка и dual-stack сокеты.
3. Оптимизация под ARM64/ARMv7: NEON-путь для ChaCha20, сборка `aarch64-unknown-linux-gnu`,
   `armv7-unknown-linux-gnueabihf`.
4. Interop-тесты как cargo-тесты с автоскипом без root (сейчас — shell-скрипты в tools/bench).
5. Перевод параллельного приёма в default-on — только после soak-тестирования на реальном
   NIC и ARM (сейчас opt-in/экспериментальный).
6. Wire-version 2 с внешним counter в FEC-шарде, чтобы отмечать
   восстановленные пакеты в ACK (общая задача с ядром).
7. Снизить FEC block timeout и сделать ранний partial flush: FEC добавляет
   ≈4–5 мс RTT (3.6–4.3 против 0.30–0.34 мс).
8. Перепроверить `rust FEC 2:1` на 0% (1.257 → 1.540) и разобрать 0.08–0.1%
   UDP-потерь на чистом канале при 400 Мбит/с.
9. AES-256-GCM и mixed ChaCha/AES — матрица в работе; AES-NI на стенде есть.
10. Multi-peer 5/10/50/100 — расширить матрицу (сейчас 1/2/4 пира).
11. BBR — держать `off` по умолчанию и не включать с FEC: на чистом канале
    −17…−24%, на потерях выигрыша нет.

## Пакетирование и релиз

- `.github/workflows/rs-packaging.yml` собирает Arch-пакет демона и не дублирует
  `tar.gz` из `rs-ci.yml`:
  - job `arch` (`archlinux:latest`) — `makepkg -f --noconfirm --nodeps` для
    `contrib/arch/umbrawg-daemon-git` (вместе с `check()` из PKGBUILD), затем
    проверка содержимого: `/usr/bin/umbrawg`, `umbrawg@.service`,
    `tmpfiles.d/umbrawg.conf` (`d /run/umbrawg 0700 root root -`), `/etc/umbrawg`
    с правами `0700`, и запуск `umbrawg --version` из распакованного пакета;
  - job `релиз` на тег `rs-v*` — `.pkg.tar.zst` + `SHA256SUMS.pkg` в GitHub Release.
- Тег должен совпадать с версией workspace (`rs-v0.4.1`); секреты не нужны,
  публикация в AUR остаётся ручной.
- Контрольные суммы разделены: `rs-ci.yml` публикует `SHA256SUMS` для `tar.gz`,
  `rs-packaging.yml` — `SHA256SUMS.pkg` для Arch-пакета, чтобы не перезаписывать
  ассет друг друга.
- `rs-ci.yml` и `rs-packaging.yml` используют собственные concurrency-группы;
  release-job дополнительно сериализован группой `release-<ref>`.
- Стабильный `contrib/arch/umbrawg-daemon` в CI не собирается: в `sha256sums`
  заглушка `TODO_UPDPKGSUMS_AFTER_FIRST_TAG`, после тега нужны `updpkgsums` и
  `makepkg --printsrcinfo > .SRCINFO`.
- Workflow проверен в Docker (makepkg, содержимое пакета, `--version`), в GitHub
  Actions ещё не запускался.

## Соглашения

- Байты на проводе и UAPI-формат совместимы с модулем ядра и Go-эталоном.
- Горячий путь без аллокаций и без `format!`/логов выше `debug`.
- Коммиты на русском, Conventional Commits; ветки `feature/*`, слияние в `master`.
