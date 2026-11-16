# UmbraWG userspace: архитектура Rust-реализации

Цель: заменить Go-реализацию (Go-версия сохранена в истории git) на Rust с сохранением
байтовой совместимости с модулем ядра `umbrawg` (протокол Noise IK + обфускация 3.1).

## Инварианты

1. Байты на проводе, номера netlink-атрибутов и UAPI-команды не меняются.
2. UAPI-совместимость: unix-сокет `/var/run/umbrawg/<iface>.sock`, команды `get=1` / `set=1`,
   формат ответов совместим с Go-версией.
3. Горячий путь без аллокаций: буферы из пула, батчинг, `recvmmsg`/`sendmmsg`.
4. Один поток на очередь (queue), без глобальных блокировок на пути пакета.
5. Поддержка Linux (TUN), сборка под x86_64 и aarch64/armv7.

## Крейты

| Крейт | Ответственность |
|---|---|
| `umbrawg-crypto` | blake2s, chacha20poly1305, x25519, tai64n, CSPRNG-обёртки |
| `umbrawg-proto` | константы и типы сообщений, заголовки, обфускация (H1-H4, S1-S4, Jc/Jmin/Jmax, I1-I5, padding, trailers), header protection |
| `umbrawg-noise` | состояние handshake (IK), вывод ключей, cookie/replay, TAI64N |
| `umbrawg-device` | Device/Peer, allowed-ips, timers, ratelimiter, очереди пакетов, state machine |
| `umbrawg-transport` | UDP-сокеты, GSO/GRO (`UDP_SEGMENT`/`UDP_GRO`), multi-queue, sticky sockets, fwmark |
| `umbrawg-tun` | TUN-устройство, multi-queue, virtio-net header, GSO/GRO offload |
| `umbrawg-uapi` | парсер/сериализатор UAPI, unix-socket сервер |
| `umbrawg` (bin) | демон: конфигурация, запуск очередей, обработка сигналов |

## Потоковая модель

```
TUN rx queue i ──> worker i ──> encrypt ──> UDP send (GSO, batch)
UDP socket j  ──> worker j ──> decrypt ──> TUN tx (GRO/offload)
```

- `n_workers = min(4, available_parallelism())`, конфигурируется `UMBRAWG_THREADS`.
- Каждый worker владеет: TUN fd (очередь), UDP fd, буферным пулом, таймером (timerfd).
- Разделяемое состояние: `Arc<Device>`, пиры в `RwLock<PeerMap>`; горячий путь читает
  `Arc<Peer>` из lock-free снимка (`arc_swap`), обновление — под write-lock.
- Ключи и handshake-состояние пира — в `RwLock<Handshake>` с быстрым read-путём.
- Таймеры: один `timerfd` на worker + wheel; никаких потоков на пира.

### Параллельный приём (`UMBRAWG_PARALLEL_RX=1`)

```
UDP socket ──> rx-поток: recvmmsg + detect + index lookup
                        │  ограниченные SPSC-очереди (64 задания)
                        ├──> крипто-воркер 0 ──> open + replay + TUN queue 0 (GSO)
                        └──> крипто-воркер N ──> open + replay + TUN queue N (GSO)
```

- По умолчанию выключен: однопоточный режим не меняется и не деградирует на 1 соединении.
- `UMBRAWG_RX_WORKERS` задаёт число крипто-воркеров; по умолчанию половина ядер, не
  больше четырёх (ядро остаётся RX-потоку, остальные — стеку, UAPI и прочей работе).
- Дейтаграмма (включая GRO-суперпакет) целиком уходит одному воркеру: порядок сегментов
  внутри неё сохраняется, GSO-склейка в TUN продолжает работать.
- Управляющие пакеты (рукопожатие, cookie) обрабатываются потоком приёма: это редкие
  события, а их состояние и так защищено локами.
- Replay-фильтр ключа — `AtomicReplayFilter` (массив `AtomicU64` c `fetch_or`): проверка
  повтора не сериализует воркеров. Переполнение очереди — дроп с счётчиком
  (`UMBRAWG_RX_STATS=1`), память ограничена: 64 задания × 64 КиБ на воркера.
- Завершение: поток приёма прекращает `recvmmsg`, воркеры дочитывают очередь и выходят
  по таймауту `poll` (10 мс), зависаний нет.

## Горячий путь (требования)

- Буферы 64 KiB, выравнивание под virtio-net header; пул на worker.
- `recvmmsg` до 64 датаграмм за вызов, `sendmmsg` с `UDP_SEGMENT` (GSO) до 64 сегментов.
- `UDP_GRO` на приёме, склейка в `virtio_net_hdr` для TUN.
- ChaCha20-Poly1305: одна инициализация состояния на пакет, без промежуточных `Vec`.
- Обфускация: заголовки H1-H4 и junk-префиксы S1-S4 формируются в тот же буфер без копий;
  I1-I5 и trailers — из предвычисленных шаблонов (аллокация только в control path).
- Никаких `format!`, `log` по уровню выше `debug` в горячем пути; счётчики — атомарные.

## Обфускация 3.1

Параметры (`H1..H4`, `S1..S4`, `Jc/Jmin/Jmax`, `I1..I5`, `HeaderProtectionKey`,
`ContentPaddingAddition`, `RandomTrailers`, `DisableCookies`) задаются через UAPI/INI
и применяются идентично модулю ядра.

Семантика (эталон — `umbrawg-linux-kernel-module/src/{peer.c,junk.c,header_protection.c,send.c,receive.c}`
и Go-реализация в `legacy/go/device/obf*.go`):

- каждый тип сообщения (1..4) получает случайный заголовок из соответствующего диапазона Hx;
- перед заголовком добавляется `Sx` случайных байт;
- junk-пакеты (Jc штук размера Jmin..Jmax) отправляются перед handshake;
- I1-I5 — специальные пакеты с тегами `<b>`, `<rc>`, `<r>`, `<t>`, `<rd>`;
- padding контента: `ContentPaddingAddition` — случайная добавка к выравниванию;
- trailers: случайный хвост после шифротекста, отбрасывается при приёме;
- header protection: ChaCha20 по части заголовка с ключом из конфигурации.

## Совместимость

- Паритетные тест-векторы handshake и обфускации против Go-реализации (`legacy/go`).
- Interop-матрица: Rust↔kernel, kernel↔Rust, Rust↔Rust, kernel↔kernel,
  с обфускацией и без, 1/4/5 пиров.
- `uwg` (Rust CLI в отдельном репозитории `umbrawg-tools`) конфигурирует и демон, и модуль.
- UAPI-ключ пира `advanced_security` принимается в `set=1` и отражается в
  `get=1` (только если был задан). Userspace-демон хранит его как
  информационное поле и не реализует advanced security; реальная защита
  доступна только в модуле ядра (`UWGPEER_A_ADVANCED_SECURITY`).

## Производительность

- Baseline: Go-реализация и оригинальный Go-демон.
- Цель: +30% на 1 ядре, +60% на 4 ядрах (TCP и UDP), без регресса обфускации.
- Профилирование: `perf record` + flamegraph, `strace -c`, счётчики softirq; правки только по профилю.
