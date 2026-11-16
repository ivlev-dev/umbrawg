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

## Измерено (пилот, 6 vCPU, 1 соединение, 1 пир, iperf3 на отдельном ядре)

| Реализация | Режим | Обф. | TCP, Мбит/с |
|---|---|---|---|
| rust | 1 ядро | вкл | 353 |
| rust | 3 ядра | вкл | 550 |
| rust | 1 ядро | выкл | 516 |
| rust | 3 ядра | выкл | 822 |
| go (эталон) | 1 ядро | выкл | 1798 |
| go (эталон) | 3 ядра | выкл | 3373 |

UDP-замеры упирались в `-b 1000M`, профиль замера нужно переделать.

## Известные проблемы

- **Горячий путь не оптимизирован**: один пакет на syscall при чтении TUN, `send_to` на датаграмму
  вместо `send_batch`, TUN открыт без offload. Поэтому Rust медленнее Go без обфускации.
- С обфускацией Go-эталон деградирует до ~4 Мбит/с — сравнение с ним требует проверки
  конфигурации эталона (вероятно, раздувание trailers), иначе цель «+30%» занижена.
- Поддержка только IPv4-сокетов (`AddressFamily::Ipv4`); IPv6-подложка не подключена.
- `RandomTrailers`/padding реализованы, но влияние на MTU/фрагментацию не отлажено.
- Android/iOS не портированы (в задаче пока не нужны).
- Первый handshake со стороны ядра теряется из-за гонки биндинга порта (см. kernel TODO).

## Что делать дальше (по приоритету)

1. Быстрый путь демона:
   - TUN с `with_offload(true)` и `write_batch_with_headers` / `read_batch`;
   - `send_batch` + GSO-сегментация на отправке;
   - GRO-склейка на приёме;
   - пул буферов на воркер, ноль аллокаций на пакет.
2. Замерить заново на стенде (`umbrawg-tools/bench`) и сравнить с Go-эталоном.
3. Профилирование: `perf record -g` на демоне, flamegraph; счётчики syscall через `strace -c`.
4. Оптимизация до +30% (1 ядро) и +60% (3 ядра) относительно Go-эталона.
5. IPv6-подложка и dual-stack сокеты.
6. Оптимизация под ARM64/ARMv7: NEON-путь для ChaCha20, сборка `aarch64-unknown-linux-gnu`,
   `armv7-unknown-linux-gnueabihf`.
7. Interop-тесты как cargo-тесты с автоскипом без root (сейчас — shell-скрипты в tools/bench).

## Соглашения

- Байты на проводе и UAPI-формат совместимы с модулем ядра и Go-эталоном.
- Горячий путь без аллокаций и без `format!`/логов выше `debug`.
- Коммиты на русском, Conventional Commits; ветки `feature/*`, слияние в `master`.
