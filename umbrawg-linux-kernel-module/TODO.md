# TODO — модуль ядра UmbraWG

## Текущее состояние

- Ветка `master`, всё слито и запушено.
- Переименование AmneziaWG → UmbraWG, `awg` → `uwg`; genl-семейство `umbrawg`, модуль `umbrawg`.
- Удалены `src/compat/` и `src/crypto/` (zinc): 35 742 → 9 077 строк (−74,6%), требуется Linux ≥ 7.0.
- Криптография — только in-kernel API: `chacha20poly1305`, `blake2s`, `curve25519`, `chacha`.
- Netlink/UAPI 3.1: полный набор атрибутов, валидация диапазонов, parity-тесты.
- Оптимизация: per-CPU очереди и батчирование крипто-воркеров в `queueing.c`, `device.c`, `send.c`.
- Профилирование пока не завершено: изменения приняты по A/B-замерам, но без полноценного `perf`-отчёта.

### Измерено (пилот, 6 vCPU, туннель на 1 ядре, iperf3 на отдельном ядре, обфускация вкл., 1 соединение, 1 пир)

| Реализация | TCP, Мбит/с |
|---|---|
| `umbrawg` (наш модуль) | 1235–1250 |
| `amneziawg` (оригинал) | 1069 |

Прирост нашего модуля относительно оригинала: **~15%**. Целевые +30% (1 ядро) и +60% (3 ядра) ещё не достигнуты.

## Сборка и проверка

```sh
cd src
make LLVM=1            # обязательно для ядер, собранных clang (Arch/CachyOS)
sudo insmod umbrawg.ko
sudo ip link add dev uwg0 type umbrawg
sudo ip link del uwg0
sudo rmmod umbrawg
```

Debug-сборка с селфтестами (allowedips, counter, ratelimiter):

```sh
make module-debug LLVM=1
```

Проверка netlink-паритета 3.1:

```sh
src/tests/netlink-parity.sh
```

## Что работает

- Noise IK, cookie, rekey/keepalive/reject-таймеры.
- Обфускация 3.1: `H1..H4`, `S1..S4`, `Jc/Jmin/Jmax`, `I1..I5`, header protection,
  `ContentPaddingAddition`, `RandomTrailers`, `DisableCookies`.
- GSO/GRO на TUN, per-CPU крипто-очереди.
- Совместимость с userspace-демоном `umbrawg` (Rust) в обе стороны, с обфускацией и без.

## Известные проблемы

- Если инициирует ядро, первая попытка handshake теряется, когда userspace-демон ещё не
  забиндил UDP-порт; соединение поднимается на ретрае через 5 с. Порядок настройки:
  сначала userspace, затем ядро.
- `make` без `LLVM=1` на clang-ядрах падает на флагах (`-fms-anonymous-structs` и др.).
- Поддержка 6.x и старее сознательно удалена.
- Полная матрица замеров (пиры, соединения, потери) ещё не прогнана.

## Что делать дальше (по приоритету)

1. Профилирование `src/receive.c`, `src/send.c`, `src/socket.c`: `perf record -g`, `perf stat`,
   `bpftrace` по `queue_work_on`, `process_one_work`, `udp_sendmsg`, `napi_gro_receive`.
2. GSO-батчирование отправки в `socket.c` (несколько пакетов одним `udp_tunnel_xmit_skb`).
3. Оптимизация приёма: батч-вычерпывание ring, отказ от лишних `skb_cow_data`, линейный fast-path
   (`receive.c`, зона одного файла).
4. Довести прирост до +30% (1 ядро) и +60% (3 ядра) без изменения байтов на проводе.
5. Полная матрица: 1/4/5 пиров × {1, 10, 100, 500} соединений × потери {0, 2, 5, 10}% ×
   {TCP 1420, UDP 1340} × {обфускация вкл/выкл}. Стенд — в `umbrawg-tools/bench`.
6. CI: сборка против 7.x, netns-тесты, `-Werror`.
7. Обновить `umbrawg-dkms.spec`/`debian` при выпуске тега.

## Соглашения

- Числовые значения netlink-атрибутов и байты на проводе менять нельзя.
- Коммиты на русском, Conventional Commits; ветки `feature/*`, слияние в `master`.
- Скрипты стенда и параметры обфускации — в `umbrawg-tools/bench`.
