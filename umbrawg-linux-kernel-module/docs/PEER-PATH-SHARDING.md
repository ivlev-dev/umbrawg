# S3: шардирование полного пути пира после replay

Документ описывает следующий шаг после отклонённого S2: параллелить не только
доставку RX, а весь тяжёлый путь одного пира, сохранив replay-семантику и
порядок пакетов внутри TCP-потока.

S1 (разрез сразу после расшифровки) и S2 (разрез только перед
`napi_gro_receive`) уже разобраны в [PEER-SHARDING.md](PEER-SHARDING.md).
S2 реализован в ветке `kernel/rx-shards` и отклонён: цель +50% не достигнута.
S3 — не повтор S2: точка разреза переносится раньше, а последовательным
остаётся только дешёвый шлюз.

> **Статус 2026-11-18: профильный гейт FAIL.** Диспетчер приёма занимает
> 28% CPU, а CPU1 насыщен на 100% (62.9% softirq veth, 36.6% sys). S3 не
> реализуется: параллелить NAPI бессмысленно, пока входной softirq одного
> внешнего UDP-потока упирается в одно ядро. Отчёт и сырые данные —
> `.local/handover/artifacts/S3-GATE-2026-11-18.md` (вне git).

## 0. Кратко

- Порядок пакетов в `master` держится не на replay-локе, а на единственном
  потребителе `peer->rx_queue`, который ждёт готовности головы
  (`src/receive.c:541-543`, `src/queueing.h:149-161`). Расшифровка при этом
  выполняется параллельно на per-CPU воркерах, а порядок восстанавливается
  очередью.
- Replay-проверка — 0.4% сэмплов диспетчера (P0). Оставлять её
  последовательной дешево, а параллелить опасно: окно и `spinlock` — единое
  состояние keypair (`src/noise.h:18-22`, `src/receive.c:381-417`).
- Основная последовательная стоимость — не replay, а `uwg_reset_packet`
  (4.3%), таймеры (5.4%), allowedips (2.0%), refcount-put (3.8%) и доставка
  (42.9–49.3%). Именно они, кроме `uwg_timers_data_received`, в S3 уходят в
  шарды.
- S3: существующий per-peer NAPI остаётся **шлюзом** (dequeue в порядке
  приёма, replay, endpoint, `udp_window`, переход keypair, `keep_key_fresh`,
  keepalive-детект), а устройство получает пул из `K` **полных
  путей-шардов**, которые делают reset, остаточные таймер-вызовы, разбор IP, trim,
  allowedips, GRO, статистику и освобождение ссылок.
- Внутри нефрагментированного TCP-потока порядок сохраняется: поток всегда
  проходит через один шлюз и один шард, кольцо — FIFO с одним потребителем.
  Кросс-потоковый порядок меняется, для IP это допустимо.
- Перед кодом обязателен **шаг 0**: профиль всего конвейера одного пира,
  включая TX-путь отправителя, а не только диспетчер приёма. Если насыщен
  softirq сокета, crypto-воркеры или TX, S3 не поможет.
- Перед кодом фиксируются две планки: цель +50% и минимум для слияния +30%
  к базе `K=1` того же прогона. База действительна только в ±5% от final4.

## 1. База, цель и критерии

### 1.1. База

Единственная база для цели — final4, TCP, один пир, медианы 3 повторов,
6 vCPU, underlay MTU 9000, TUN 1420 (`docs/PERFORMANCE.md`, «Единый замер
final4»):

| Ячейка | obf0 | obf1 |
|---|---:|---:|
| `3c c10` | 2056.4 | 1875.3 |
| `3c c1` | 2430.0 | 2252.9 |
| `1c c1` | 2344.6 | 2267.9 |

Мбит/с. База `K=1` снимается в том же прогоне; прошлые прогоны — только
ориентир. Стенд дрейфует: final4 `2056.4/1875.3`, P0 master
`1835.9/1635.4` (−10.7/−12.8%), S2 K=1 `1901.1/1679.6` (−7.5/−10.4%).
Поэтому база `K=1` действительна только если попала в **±5%** от
2056.4/1875.3. Иначе прогон переснимается, а не считается от низкой базы;
в отчёт всегда пишется дельта базы к final4. Если после двух попыток база
не воспроизводится, стенд считается изменившимся: абсолютный пол 3090/2810
не применяется, решение принимается по планке +30% и контролям, с явной
пометкой «absolute floor not comparable».

### 1.2. Цель и две планки

- **Цель:** `3c c10` при `K>1` — **≥ ~3090 Мбит/с** (obf0) и
  **≥ ~2810 Мбит/с** (obf1), то есть +50% к final4. Абсолютный пол
  действует только при действительной базе `K=1` из 1.1.
- **Минимум для слияния:** **≥ +30%** к базе `K=1` того же прогона при
  нулевых/околонулевых дропах и подтверждённом профиле («работа уехала в
  шарды»). Обе планки фиксируются до замеров и не меняются после.
- **Контроли:** `3c c1`, `1c c1` и `1c c10` — нейтрально в пределах
  измеренного шума. Роста здесь не требуется.
- **UDP:** не хуже разброса; ячейки и ставка задаются явно (11.1).
- **Латентность:** p99 не хуже более чем на 10% (планка приёмки); рост
  более чем на 20% — аварийный стоп.
- **Стабильность:** нет `WARN`/`BUG`, утечек потоков и skb, роста дропов
  туннеля; `ring_full` в целевой ячейке — **0** на всех повторах, иначе
  ячейка не принимается.

### 1.3. Почему цель достижима — с оговоркой

P0 дал `Y/X ≈ 1.0` и покрытие poll 65.6–69.1% сэмплов потока диспетчера.
Но 31–34% сэмплов потока — вне poll (планировщик, IPI, softirq), и они не
исчезнут от шардирования; с K потоками часть из них вырастет. Честная
верхняя оценка последовательной части — `0.31 + ~0.10 ≈ 0.41`, то есть
потолок `≈ 2.4×` без накладных; с кольцами, пробуждениями и
refcount-контеншеном реалистично **1.3–1.7×**. Цель +50% лежит в этом
диапазоне, но запаса на ошибки почти нет.

S2 параллелил только Y и получил +0…+6.6%, в отдельных ячейках до −8.8%.
S3 параллелит ещё и тяжёлый X, который в S2 оставался в диспетчере. Если
профильный гейт покажет, что диспетчер не насыщен или насыщен не он, цель
недостижима этим путём, и S3 не реализуется.

Отдельное ограничение: шлюз ждёт готовности головы `rx_queue`
(`receive.c:541-543`), поэтому один медленный decrypt стопорит все потоки
пира (head-of-line blocking). Это не лечится шардированием после `rx_queue`
и входит в верхнюю оценку.

## 2. As-built: где сейчас сериализация

Путь одного DATA-пакета в `master`:

```
udp encap_rcv (socket.c:357-368)
  → uwg_packet_receive (receive.c:643)
  → uwg_packet_consume_data (receive.c:610)
      rcu_read_lock_bh, lookup keypair/peer (receive.c:616-622)
      uwg_queue_enqueue_per_device_and_peer (queueing.h:183-208)
        → prev_queue_enqueue(peer->rx_queue)  порядок фиксируется здесь
        → per-CPU decrypt ring, round-robin CPU
  → decrypt worker (receive.c:588-608), параллельно на 0..N CPU
      decrypt_packet (receive.c:328-378)
      state = CRYPTED/DEAD, napi_schedule(peer->napi) (queueing.h:223-233)
  → per-peer threaded NAPI, uwg_packet_rx_poll (receive.c:527-586)
      ждёт голову rx_queue, пока state == UNCRYPTED
      counter_validate (receive.c:551)
      endpoint_from_skb (receive.c:560)
      udp_window (receive.c:564-566)
      uwg_reset_packet (receive.c:568)
      consume_data_done (receive.c:421-525)
        set_peer_endpoint, keypair slide, keep_key_fresh, таймеры,
        keepalive, разбор IP, trim, allowedips, napi_gro_receive,
        статистика, put ссылок
```

Что сериализовано:

| Участок | Чем сериализован |
|---|---|
| чтение UDP-сокета | нет uwg-лока, softirq может работать на разных CPU |
| `rx_queue` | multi-producer / single-consumer (`queueing.c:121-177`) |
| расшифровка | параллельна, порядок завершения произволен |
| replay | `spin_lock_bh` на keypair (`receive.c:386`) |
| endpoint | fast-path без лока, `write_lock_bh` при смене (`socket.c:313-338`) |
| таймеры | таймер-база, `mod_timer`/`timer_delete`; проверка `is_dead` в `mod_peer_timer` (`timers.c:32-41`) |
| keypair slide | `spin_lock_bh(keypair_update_lock)`, редкий путь (`noise.c:255-292`) |
| allowedips | RCU, без локов (`allowedips.c:127-147`) |
| доставка/GRO | один `napi_struct` пира ⇒ один поток (`receive.c:500`) |
| статистика | `dev_sw_netstats_rx_add` per-CPU; `peer->rx_bytes +=` не атомарно (`receive.c:22-26`) |

Ключевой факт: per-peer лока в fast-path нет. Порядок держится на
единственном потребителе `rx_queue` и единственном NAPI-потоке. Любой разрез
до `rx_queue` теряет порядок, потому что decrypt-воркеры завершаются
произвольно.

## 3. Чем S3 отличается от S1 и S2

| Вариант | Точка разреза | Что параллелится | Почему не подошёл |
|---|---|---|---|
| S1 | в decrypt-воркере, сразу после расшифровки | replay, endpoint, trim, allowedips, GRO | порядок теряется; replay-лок конкурирует; нужен reorder-буфер |
| S2 | перед `napi_gro_receive` | только GRO/стек | +0…+6.6%, местами регрессия до −8.8%: тяжёлый X остался в диспетчере |
| **S3** | **в per-peer NAPI после replay и stateful-пролога** | reset, остаточные таймер-вызовы, IP, trim, allowedips, GRO, статистика, put | — |

S3 не двигает replay в шарды. Он остаётся в шлюзе, который и так читает
`rx_queue` в порядке приёма. Шарды получают уже валидированные пакеты в том
же порядке, в котором их разбирает шлюз.

## 4. Архитектура S3

### 4.1. Топология

```
                    один пир
UDP softirq → decrypt workers (параллельно)
                    │
                    ▼
            peer->rx_queue (ordered gate)
                    │
        per-peer NAPI = шлюз (K=1 и K>1)
        replay, endpoint, udp_window,
        keypair slide, keep_key_fresh, hash
                    │
        ┌───────────┼───────────┬───────────┐
        ▼           ▼           ▼           ▼
     shard 0     shard 1     shard 2     shard 3      (пул устройства)
     reset       reset       reset       reset
     timer del   timer del   timer del   timer del
     IP/trim     IP/trim     IP/trim     IP/trim
     allowedips  allowedips  allowedips  allowedips
     GRO         GRO         GRO         GRO
     stats       stats       stats       stats
     put         put         put         put
```

- Шарды — пул **на устройство**, а не `K × пиры`: `K` потоков и `K` NAPI на
  устройство.
- `K=1` — прежний путь без аллокаций и без кольца. Это обязательное условие
  обратной совместимости и контроль в замерах.
- `K = clamp(module_param, 1, 16, num_online_cpus())`. Значение фиксируется
  при создании устройства; существующие устройства не перестраиваются.
- Имя параметра — `rx_path_shards`, `default=1` (opt-in), чтобы не
  конфликтовать с `rx_shards` экспериментальной ветки S2. Рекомендуемый
  `K` по умолчанию фиксируется до слияния (этап 6).

### 4.2. Точка разреза

Шлюз (существующий `uwg_packet_rx_poll`) выполняет:

1. ожидание головы `rx_queue` и извлечение skb;
2. `counter_validate`;
3. `uwg_socket_endpoint_from_skb`;
4. обновление `peer->udp_window`;
5. `uwg_socket_set_peer_endpoint` — строго после `udp_window`, как в
   `master`: смена endpoint сбрасывает `udp_window` в `DEFAULT_UDP_WINDOW`
   (`socket.c:337`), и порядок шагов влияет на размер трейлера;
6. `uwg_noise_received_with_keypair` + `uwg_packet_send_staged_packets`,
   если подтверждён новый keypair;
7. `keep_key_fresh`;
8. определение keepalive по первому байту, запись
   `PACKET_CB(skb)->is_keepalive`, и `uwg_timers_data_received` для
   не-keepalive. Это остаётся в шлюзе, чтобы не ловить TOCTOU на
   `timer_need_another_keepalive` и `timer_pending`;
9. чтение `PACKET_CB(skb)->rx_hash` (посчитан в decrypt-воркере);
10. постановка skb в кольцо выбранного шарда и пробуждение.

Поллер шарда выполняет:

1. проверку `READ_ONCE(peer->is_dead)`; мёртвый пир — дроп с `put`/free;
2. вызов `uwg_packet_rx_finish(peer, skb, &shard->napi, shard)`, который
   делает:
   1. `uwg_reset_packet(skb, false)`;
   2. `uwg_timers_any_authenticated_packet_received` и
      `uwg_timers_any_authenticated_packet_traversal`;
   3. если `PACKET_CB(skb)->is_keepalive` — статистика и выход;
   4. проверку сетевого заголовка, ECN, `skb->protocol`, `skb->dev = dev`,
      `ip_summed = CHECKSUM_UNNECESSARY`, `csum_level = ~0`, `pskb_trim`;
   5. `uwg_allowedips_lookup_src` и сверку с пиром;
   6. **до GRO** сохранить локально `peer`, `keypair` и `len_before_trim`;
   7. `napi_gro_receive(&shard->napi, skb)`;
   8. статистику по локальным копиям (per-shard `packets/bytes`, `peer`
      `rx_bytes`, `dev_sw_netstats_rx_add`) и ровно один `keypair_put` +
      `peer_put`; при дропе — `dev_kfree_skb`.

Инвариант: `napi_gro_receive` использует `skb->cb` под `NAPI_GRO_CB`
(`include/net/gro.h:100`), поэтому после GRO нельзя читать `PACKET_CB(skb)`
и `PACKET_PEER(skb)`: там уже данные GRO, а при `GRO_CONSUMED` skb
освобождён. Всё нужное снимается до вызова GRO. Это тот же класс ошибки,
что UAF в S2 (`d812dec5`).

Почему endpoint и `keep_key_fresh` остаются в шлюзе:

- `uwg_socket_set_peer_endpoint` меняет per-peer состояние и сбрасывает
  `udp_window` (`socket.c:313-338`); при нескольких шардах порядок обновлений
  между потоками может стать произвольным. Стоимость в шлюзе — 1.1%.
- `keep_key_fresh` и переход keypair — редкий путь с флагом
  `sent_lastminute_handshake` и вызовом `send_staged_packets`. Держать его в
  одном потоке дешевле, чем добавлять атомики и риск дублей handshake.
- `udp_window` — простая пара `READ_ONCE`/`WRITE_ONCE`, в шлюзе почти
  бесплатна.
- `uwg_timers_data_received` остаётся в шлюзе: она трогает
  `timer_need_another_keepalive` и `timer_pending`/`mod_timer`, а гонка K
  потоков может потерять keepalive или отодвинуть дедлайн. Остальные
  таймер-вызовы (`any_authenticated_packet_received/traversal`) уходят в
  шард.

Почему остальные таймеры можно в шард: `mod_peer_timer` проверяет `is_dead`
под `rcu_read_lock_bh` (`timers.c:32-41`), а `synchronize_net()` в
`uwg_peer_remove()` (`src/peer.c:163-165`) ждёт завершения всех
предшествующих RCU-секций. После него новые вызовы видят `is_dead` и не
взводят таймер. `timer_delete`/`timer_delete_sync` в `uwg_timers_stop`
(`timers.c:260-267`) безопасны, потому что после остановки ничего не
взводится; `is_dead` в шарде — ранний выход, а не механизм синхронизации.

### 4.3. Структуры

```c
#define UWG_MAX_RX_PATH_SHARDS 16
#define UWG_RX_PATH_RING_MIN 256
#define UWG_RX_PATH_RING_TOTAL 4096

struct uwg_rx_path_shard {
    struct napi_struct napi;
    struct ptr_ring ring;
    atomic_t pending;
    atomic64_t packets;
    atomic64_t bytes;
    atomic64_t ring_full;
    atomic64_t keepalive;
    atomic64_t dead_drop;
    atomic64_t allowedips_drop;
    atomic64_t dishonest_size;
    atomic64_t dishonest_type;
    atomic64_t trim_fail;
    atomic64_t unparsed;
    atomic64_t fragmented;
};

struct uwg_device {
    ...
    struct uwg_rx_path_shard *rx_path_shards;
    u32 rx_path_shards_num;
    atomic64_t rx_replay_drop;
    atomic64_t rx_endpoint_drop;
};
```

Счётчики отдаются netdev-атрибутом `rx_path_shards` (`0400`), по строке на
шард плюс строка шлюза. Имя отличается от `rx_shards` из ветки S2, чтобы
ветки не путались при сравнении. Формат: `shard idx packets bytes ring_full
keepalive dead_drop allowedips_drop dishonest_size dishonest_type trim_fail
unparsed fragmented`.

`PACKET_CB` дополняется одним полем:

```c
#define UWG_RX_FLAG_FRAGMENTED  BIT(0)
#define UWG_RX_FLAG_UNPARSED    BIT(1)

struct packet_cb {
    ...
    bool is_keepalive;
    u8 rx_flags;
    u32 rx_hash;
};
```

Текущий `struct packet_cb` занимает 40 байт из 48. `rx_flags` и `rx_hash`
встают в существующий padding, размер не меняется; `BUILD_BUG_ON(sizeof(struct
packet_cb) > sizeof(((struct sk_buff *)0)->cb))` выносится на file scope.
`rx_len` в S3 не нужен: длина снимается локально до `pskb_trim`.
`PACKET_PEER(skb)` по-прежнему разыменовывает `keypair->entry.peer`; все
нужные указатели снимаются до GRO, иначе UAF (этот класс бага чинился в S2
коммитом `d812dec5`).

### 4.4. Разделение `consume_data_done` и контракт владения

Функция `uwg_packet_consume_data_done` (`receive.c:421-525`) делится на две
части; поведение `K=1` сохраняется, а немногочисленные отличия перечислены
ниже. Владение задаётся **единственным** правилом: после успешного возврата
из `gate` поллер не трогает ни ссылки, ни skb.

```c
enum uwg_rx_gate_result {
    UWG_RX_GATE_RETURNED,   /* gate не забрал владение */
    UWG_RX_GATE_TAKEN,      /* gate/finish/deliver уже освободили или передали */
};

enum uwg_rx_gate_result uwg_packet_rx_gate(struct uwg_peer *peer,
                                           struct sk_buff *skb);
void uwg_packet_rx_finish(struct uwg_peer *peer, struct sk_buff *skb,
                          struct napi_struct *napi,
                          struct uwg_rx_path_shard *shard);
```

- `uwg_packet_rx_gate()` — шаги 1–10 из 4.2. На путях `state != CRYPTED`,
  replay-error, endpoint-error он сам делает `put`/`dev_kfree_skb` и
  возвращает `TAKEN`. На успехе:
  - `K=1` — вызывает `uwg_packet_rx_finish(peer, skb, &peer->napi, NULL)`,
    `finish` владеет и освобождает, возвращает `TAKEN`;
  - `K>1` — вызывает `uwg_rx_path_deliver()`, который забирает владение
    безусловно, и возвращает `TAKEN`.
- `uwg_packet_rx_finish()` — внутренние шаги 2.1–2.8 из 4.2 (без `is_dead`),
  где `napi` — `&peer->napi` или `&shard->napi`, `shard` — статистика шарда
  или `NULL` для `K=1`.
- Поллер на метке `next:` делает `put`/`free` **только** при
  `UWG_RX_GATE_RETURNED`. На практике это путь `state == UNCRYPTED`, который
  цикл и так не пропускает; все остальные пути возвращают `TAKEN`.

| Путь | Кто делает `keypair_put` + `peer_put` | Кто делает `dev_kfree_skb` |
|---|---|---|
| state != CRYPTED / replay / endpoint error | `gate` | `gate` |
| `K=1`, keepalive/drop/deliver | `finish` | `finish` на drop |
| `K>1`, успешная постановка в кольцо | шард | шард на drop; GRO может потребить skb |
| `K>1`, `ptr_ring_produce_bh` error | `uwg_rx_path_deliver` | там же |
| шард, `is_dead` | шард | шард |
| teardown, дренаж | дренаж | дренаж |

`uwg_rx_path_deliver()` забирает владение **безусловно**: при переполнении
кольца он сам снимает ссылки и уничтожает skb, а не возвращает пакет шлюзу.
Поэтому в поллере нет флагов `free`/`deferred`: после `gate` всегда
`TAKEN`, и `next:` не делает повторный `put`. Это исключает двойной `put`
на ошибке кольца.

Проверка `is_dead` — не часть `finish`: её делает `uwg_rx_path_poll` перед
вызовом `finish`, а при `K=1` её нет, как в `master`.

Для `K=1` обязаны остаться неизменными относительно `master`:

- один NAPI-поток на пира, без кольца и без `pending`;
- `napi_complete_done` только при `work_done < budget`;
- точки статистики: `message_data_len(len_before_trim)` для data и
  `message_data_len(0) + skb->len` для keepalive;
- порядок освобождения `keypair_put` → `peer_put` → `dev_kfree_skb`;
- отсутствие проверки `is_dead` в `finish`: в `master` пакеты, уже стоящие
  в `rx_queue`, обрабатываются после смерти пира (`receive.c:624`);
- порядок `udp_window` → `set_peer_endpoint`;
- отсутствие хэширования в decrypt-воркере: хэш считается только при
  `READ_ONCE(rx_path_shards_num) > 1`, как в S2.

`peer->rx_bytes` переводится в `atomic64_t` для обоих режимов, потому что
поле должно иметь один тип. Это единственное отличие по типам данных; кроме
него меняются порядок `uwg_timers_data_received` относительно
`any_authenticated_*`, положение `uwg_reset_packet` (после `set_peer_endpoint`
вместо до) и источник keepalive-флага. Эти перестановки не меняют поведение:
таймеры независимы, `reset` не трогает endpoint/timers, а флаг
`is_keepalive` вычисляется из тех же байтов. Цена проверяется A/B `master`
против S3 с `rx_path_shards=1` (этап 2.5). Читатель `UWGPEER_A_RX_BYTES`
(`netlink.c:333`) переводится на `atomic64_read`.

### 4.5. Хэш потока

Хэш считается в decrypt-воркере после успешной расшифровки и только при
`READ_ONCE(rx_path_shards_num) > 1`, как в S2 (`kernel/rx-shards`,
`uwg_rx_flow_hash`). Это параллельный контекст, шлюз только читает готовое
значение. Для `K=1` хэш не считается.

API получает `bool *parsed`: успешный разбор с легитимным `hash == 0`
отличается от неудачи. При `!parsed` ставится флаг `UNPARSED`, пакет идёт в
шард 0, а шард инкрементирует `unparsed`. При `ip_is_fragment()` ставится
флаг `FRAGMENTED` и шард инкрементирует `fragmented`. Так оба счётчика
принадлежат шарду и не требуют отдельного поля в устройстве. Для keepalive
(пустой payload) `UNPARSED` снимается в шлюзе после детекта: это штатный
пакет, а не ошибка разбора; шард 0 обрабатывает его по флагу
`is_keepalive`.

Правила:

- TCP: 4-tuple (src, dst, sport, dport) плюс protocol;
- UDP/QUIC: 4-tuple + protocol; иначе весь UDP липнет к шарду 0 и остаётся
  последовательным;
- ICMP: hash по паре адресов, протоколу и типу/коду;
- нераспознанное: hash по паре адресов и протоколу;
- infix: `idx = (u64)hash * K >> 32`;
- парсер ограничен первыми 128 байтами и 8 заголовками IPv6, как в S2;
- selftest расширяется на UDP, ICMP, IPv4/IPv6-фрагменты и стабильность при
  изменении TTL/checksum. Старая проверка S2 «UDP → 0» заменяется: UDP и
  ICMP теперь хэшируются, это осознанное расхождение с S2.

**Фрагменты — отдельное правило.** Хэш по 4-tuple + protocol доступен только у первого
фрагмента (`offset == 0`); у последующих портов нет. Если хэшировать первые
фрагменты по 4-tuple + protocol, а остальные по `ip_id`, одна TCP-датаграмма
разъедется по двум шардам и порядок потока сломается. Поэтому:

- при `ip_is_fragment()` хэш считается по `ip_id`/`identification` и
  протоколу (в IPv4 — `protocol`, в IPv6 — `nexthdr`); это держит все
  фрагменты одной датаграммы вместе;
- гарантия порядка в 5.1 формулируется **только для нефрагментированных
  потоков**. Для потока, часть датаграмм которого фрагментирована, порядок
  между фрагментированной датаграммой и обычными сегментами не
  гарантируется;
- на стенде фрагментов на проводе 0 (GSO, `docs/PERFORMANCE.md`), поэтому в
  целевых ячейках это не проявляется; счётчик `fragmented` в sysfs обязателен;
- если фрагментация станет реальной, следующий шаг — мини-таблица
  `(saddr, daddr, proto, ip_id) → shard` с TTL на устройство, чтобы
  последующие фрагменты находили шард первого. В первый прототип она не
  входит.

`hash == 0` — валидный индекс шарда 0. Отдельный счётчик `unparsed` нужен не
для fallback, а для диагностики: `uwg_rx_flow_hash` возвращает `0` и при
неудачном разборе (короткий skb, `ihl < 5`, слишком много заголовков IPv6).
Если таких пакетов много, поток может расщепиться между шардом 0 и остальными;
`unparsed` в sysfs и проверка в тестах обязательны.

## 5. Порядок, ссылки и владение

### 5.1. Порядок

- `rx_queue` остаётся single-consumer: шлюз — единственный, кто её читает.
- Шлюз разбирает пакеты строго в порядке `rx_queue` (ожидание `CRYPTED` на
  голове) и ставит их в кольцо шарда в этом же порядке.
- У каждого пира свой шлюз, поэтому пакеты потока проходят через один шлюз:
  внутренний src уникален в `allowedips`, один поток не может размазаться по
  двум пирам. Для устройства с `N` пирами кольцо шарда — **MPSC**:
  производителей `N` (по одному шлюзу на пира), потребитель один.
- Хэш потока детерминирован для нефрагментированных пакетов, поэтому все
  пакеты одного TCP-потока попадают в один шард, а кольцо шарда — FIFO с
  одним потребителем.
- Внутри нефрагментированного потока относительный порядок такой же, как в
  `master`. Кросс-потоковый порядок меняется; для IP это допустимо, для
  TCP-потока — нет.
- Keepalive не имеет внутреннего потока. Он уходит в шард 0 и не влияет на
  TCP-потоки, кроме собственного кольца. При многих пирах шард 0 получает
  все keepalive'ы устройства — это отдельный хотспот, см. риск 3.
- Смена `allowedips` посреди потока переводит поток на другого пира и в
  другое кольцо; это редкое событие конфигурации, а не свойство S3.

### 5.2. Ссылки

На пакет ровно один `keypair_put` и один `peer_put`:

- ingress берёт ссылки: `uwg_index_hashtable_lookup` с `&peer`
  (`peerlookup.c:202-225`) и `uwg_noise_keypair_get` (`receive.c:621`);
- `K=1` — освобождает шлюз после `uwg_packet_rx_finish`;
- `K>1` — освобождает шард после обработки;
- переполнение кольца — освобождает шлюз, skb уничтожается;
- teardown — дренаж освобождает ссылки.

Порядок освобождения: сохранить `peer` и `keypair` **до** `napi_gro_receive`,
затем после GRO — `keypair_put`, `peer_put`, и `dev_kfree_skb` только на
дропе. Обратный порядок или чтение `PACKET_CB`/`PACKET_PEER` после GRO даёт
UAF: GRO перезаписывает `skb->cb`, а при `GRO_CONSUMED` освобождает skb.

### 5.3. Мёртвый пир

- Шард проверяет `READ_ONCE(peer->is_dead)` первым делом. Если пир мёртв —
  дроп без таймеров, allowedips и GRO.
- Ссылка на пира из skb держит память живой до `put`, поэтому проверка
  безопасна и без отдельного лока.
- `peer_make_dead()` + `synchronize_net()` (`peer.c:163-165`) гарантируют,
  что новые `mod_peer_timer` увидят `is_dead` и не взведут таймер: проверка
  идёт под `rcu_read_lock_bh` (`timers.c:32-41`). Они **не** покрывают
  `timer_delete` в шарде; он безопасен только потому, что после
  `uwg_timers_stop` ничего не взводится, а keypair жив refcount'ом skb.
- Удаление пира при живом устройстве кольца не дренирует: пакеты в кольцах
  держат ссылки и будут отброшены шардом по `is_dead`.
- Replay-окно к этому моменту уже сдвинуто шлюзом: валидация идёт до дропа.
  В `master` дроп по `is_dead` возможен только до постановки в `rx_queue`;
  пакеты, уже стоящие в очереди, валидируются и после смерти пира. S3
  сохраняет это поведение, а шард лишь добавляет ранний выход. Оптимизировать
  его, пропуская `counter_validate`, нельзя.

## 6. Жизненный цикл

### 6.1. Создание

Порядок в `uwg_newlink`:

1. `netif_threaded_enable(dev)`;
2. `uwg_rx_path_shards_init(uwg)`;
3. `register_netdevice(dev)`.

Внутри init:

1. вычислить `K`; если `K == 1`, вернуться без аллокаций и оставить
   `rx_path_shards_num = 1`;
2. опубликовать `rx_path_shards_num = 1` до аллокаций;
3. `kcalloc_node` массива;
4. на каждый шард: `ptr_ring_init` → `set_bit(NAPI_STATE_NO_BUSY_POLL)` →
   `netif_napi_add_weight(dev, &shard->napi, uwg_rx_path_poll, NAPI_POLL_WEIGHT)`
   → `napi_enable`; после каждого успешного шарда обновлять локальный
   счётчик созданных;
5. `smp_store_release(rx_path_shards_num, K)`.

Ошибка на любом шаге — откат только уже созданных шардов (`napi_disable` →
`netif_napi_del` → `ptr_ring_cleanup`), `kfree` массива и
`smp_store_release(rx_path_shards_num, 1)`. Нельзя вызывать
`napi_disable`/`netif_napi_del` для шарда, который не прошёл `napi_enable`.

Отдельная ветка — ошибка `register_netdevice()`: `priv_destructor` ещё не
назначен (`device.c:393-396`), поэтому `uwg_destruct` не вызовется. Нужен
явный `uwg_rx_path_shards_uninit(uwg)` перед `err_uninit_ratelimiter`, иначе
`K` NAPI-потоков, кольца и массив утекут.

### 6.2. Удаление устройства

`uwg_destruct`:

1. `uwg_peer_remove_all(uwg)` — останавливает все per-peer NAPI-шлюзы;
2. `uwg_rx_path_shards_uninit(uwg)`;
3. `destroy_workqueue`, `rcu_barrier`.

Внутри uninit:

0. если `rx_path_shards == NULL` (режим `K=1`), выйти;
1. прочитать `n = READ_ONCE(rx_path_shards_num)`;
2. `napi_disable` всех `n` шардов — новые пакеты не обрабатываются;
3. дренаж всех `n` колец: `keypair_put`, `peer_put`, `dev_kfree_skb`;
4. `netif_napi_del` всех `n` шардов;
5. `WARN_ON(!__ptr_ring_empty())`, при необходимости повторный дренаж;
6. `ptr_ring_cleanup` всех `n` шардов;
7. `smp_store_release(rx_path_shards_num, 1)` — последним;
8. `kfree` массива.

Порядок с `n` в начале и публикацией `1` в конце обязателен: если читать
`rx_path_shards_num` после публикации `1`, будут сняты и очищены только
шард 0, а шарды `1..K-1` останутся с `napi_enable` и потеряются при `kfree`
(утечка kthread'ов и UAF). `smp_store_release` — только advisory: новые
постановки запрещает остановка производителей, а не значение параметра.

Инвариант: к моменту uninit все производители остановлены. Его обеспечивает
`uwg_peer_remove_all`, который дважды флашит `packet_crypt_wq` и делает
`napi_disable` каждого шлюза (`peer.c:116-125`). Uninit обязан идти до
`kvfree(uwg->index_hashtable)` и `free_netdev`: дренаж — последний
потребитель refcount'ов, а `keypair_free_kref` и `kref_release` трогают
`index_hashtable`, `staged_packet_queue` и `peer->device` (`noise.c:119-131`,
`peer.c:201-222`).

## 7. Гонки per-peer состояния

При `K>1` несколько шардов одновременно обрабатывают пакеты одного пира.
Состояние, которое сейчас защищено единственным NAPI-потоком, нужно
защитить явно.

| Поле | Сейчас | В S3 |
|---|---|---|
| `peer->rx_bytes` (`receive.c:25`) | `+=` | `atomic64_t`, `atomic64_add`; `netlink.c:333` → `atomic64_read` |
| `peer->udp_window` (`receive.c:564-566`) | `WRITE_ONCE` | остаётся в шлюзе, без изменений |
| `peer->endpoint` | `write_lock_bh`, fast-path | остаётся в шлюзе |
| `sent_lastminute_handshake` (`receive.c:307-326`) | bool | остаётся в шлюзе |
| `timer_need_another_keepalive` (`timers.c:168-180`) | bool | `uwg_timers_data_received` остаётся в шлюзе; в шарде поле не трогается |
| `timer_handshake_attempts`, `max_handshake_attempts`, `walltime_last_handshake` | таймер/`handshake_complete`, netlink | `handshake_complete` остаётся в шлюзе; netlink-читатели не меняются |
| `peer->is_dead` | `READ_ONCE` | `READ_ONCE` в шарде; это семантика, а не механизм teardown |
| `dev_sw_netstats_rx_add` | per-CPU | без изменений, но вызов из шарда |
| `DEV_STATS_INC(dev, rx_errors/…)` | per-CPU | без изменений, вызов из шарда |
| `keypair slide` | `keypair_update_lock` | остаётся в шлюзе |
| `timer_*` как объекты | `mod_timer`/`timer_delete` | в шарде только `timer_delete` и `mod_peer_timer`, который сам проверяет `is_dead` под RCU |
| `allowedips` | RCU | без изменений, только чтение |
| refcount'ы | атомарные | без изменений; возможен cacheline bouncing |

Правило: per-peer поля, меняющиеся на каждом пакете и требующие порядка,
остаются в шлюзе. В шард уходит только то, что либо skb-local, либо уже
защищено внутренним локом/RCU.

Отдельный инвариант teardown: шард не разыменовывает keypair, кроме
`keypair_put`; не вызывает `uwg_noise_received_with_keypair`,
`keep_key_fresh` и `send_staged_packets`; не взводит новых таймеров в обход
`mod_peer_timer`. `is_dead` в шарде — ранний выход, а не синхронизация:
`peer_make_dead()` + `synchronize_net()` покрывают только RCU-секции
`mod_peer_timer`, но не `timer_delete`. Безопасность `timer_delete`
держится на том, что после `uwg_timers_stop` ничего не взводится.

Логи шарда (`dishonest_packet_*`, keepalive) не печатают
`peer->endpoint.addr`: endpoint пишется шлюзом под `write_lock_bh`, а чтение
из шарда — гонка. В шарде остаётся `peer->internal_id` и `dev->name`.

## 8. Кольца, пробуждение и переполнение

### 8.1. Кольцо

- `ptr_ring`, производители — шлюзы пиров (MPSC, `producer_lock` сериализует
  постановку), потребитель один — NAPI шарда.
- Размер: `max(UWG_RX_PATH_RING_MIN, UWG_RX_PATH_RING_TOTAL / K)`, где
  `UWG_RX_PATH_RING_TOTAL = 4096`, `UWG_RX_PATH_RING_MIN = 256`. При `K=2` —
  2048, при `K=4` — 1024, при `K=8` — 512, при `K=16` — 256. Суммарно на
  устройство — не больше 4096 указателей (32 КБ), сами skb уже в полёте.
  Формула учитывает горячий шард и несколько пиров: `rx_queue` вмещает 1024
  на пира, поэтому кольцо не должно быть меньше 512 при `K<=8`.
- `ptr_ring_produce_bh` в шлюзе; на ошибке — дроп только этого пакета,
  `ring_full++`, `rx_dropped++`, ссылки снимает шлюз.
- `producer_lock` — общая cacheline для всех шлюзов устройства. При многих
  пирах это точка контеншена; она входит в риск 12 и измеряется отдельно.

### 8.2. Пробуждение

- На шард — `atomic_t pending`.
- Шлюз: `if (!atomic_xchg(&shard->pending, 1)) napi_schedule(&shard->napi);`
- Поллер при `work_done == budget` возвращает бюджет и **не** вызывает
  `napi_complete_done` и не сбрасывает `pending`: NAPI перезапустится сам.
- Поллер при `work_done < budget`:
  1. `napi_complete_done(&shard->napi, work_done)`;
  2. `atomic_xchg(&shard->pending, 0)` — full barrier, аналог `smp_mb()` в
     `uwg_queue_wakeup_drained` (`queueing.h:172-181`);
  3. `if (!__ptr_ring_empty(&shard->ring)) napi_schedule(&shard->napi);`
- Проверка кольца строго после complete и после сброса `pending`. Без
  барьера на weakly-ordered CPU чтение кольца может выполниться раньше
  записи флага, и пробуждение потеряется — тот же баг, что чинился в S2
  (`d812dec5`).
- `napi_schedule` сам коалесится через `NAPI_STATE_SCHED`
  (`netdevice.h:560-568`), поэтому `pending` — не замена коалесинга, а
  попытка сэкономить на общем RMW. Выигрыш измеряется; если его нет,
  `pending` убирается в пользу прямого `napi_schedule`, как в S2.
- Бюджет шарда — `NAPI_POLL_WEIGHT` (64). При постоянном заполнении
  `napi_complete_done` не вызывается, GRO-флаш откладывается; поэтому p99
  и jitter — обязательные метрики, а не только throughput.

### 8.3. Переполнение

- Backpressure из шарда в шлюз запрещён: шлюз не может спать в NAPI.
- Fallback в другой шард запрещён: он ломает порядок потока.
- Синхронная обработка в шлюзе запрещена по той же причине: пакет обгонит
  ранее поставленные в кольцо пакеты того же потока.
- Остаётся дроп. Риск смягчается размером кольца и коалесингом
  пробуждений; `ring_full` — обязательная метрика приёмки.
- Если `ring_full` окажется систематическим, следующий шаг — не fallback, а
  per-flow очередь с явным лимитом или изменение хэша/числа шардов.

## 9. Шаг 0: профильный гейт

P0 мерил только поток диспетчера. Для S3 нужно понять, какое звено
конвейера насыщено.

### 9.1. Что снять

Стенд P0: 6 vCPU, veth underlay 9000, TUN 1420, 1 пир, `3c`, `c10`,
iperf3 на CPU 3, workqueue 0-2, 30 с, 3 повтора, obf0/obf1.

На каждом повторе:

- `mpstat -P ALL 1` — `%usr`, `%sys`, `%soft`, `%irq`, `%idle` по CPU;
- `pidstat -t -u -p ALL 1` или `ps -eLo pid,tid,psr,comm,pcpu` — по потокам:
  `napi/uwgb1-0`, `napi/uwgb0-0`, crypto-воркеры, `ksoftirqd/*`, iperf3;
- `/proc/<tid>/schedstat` для диспетчера и TX-воркера: `runtime`,
  `run_delay`, число срезов. Это отличает «работает» от «ждёт крипту»;
- `perf stat -a -e cycles,instructions,context-switches,cpu-migrations` —
  30 с;
- `/proc/softnet_stat` и `/proc/softirq` до/после — `processed`, `dropped`,
  `time_squeeze`, `NET_RX` по CPU;
- `ip -s link` на veth и на uwg-интерфейсах;
- `perf record -t <диспетчер>` — как в P0, для контроля доли poll;
- `perf record` по отправителю: `uwg_xmit`, TX-воркер
  (`transmit_packet_work`), crypto-воркеры шифрования, `udp_sendmsg`.

### 9.2. Гейт

S3 реализуется, только если одновременно:

1. диспетчер `napi/uwgb1-0` загружен **≥ 85% одного CPU**, а по `schedstat`
   `runtime / (runtime + run_delay) ≥ 0.9`: он именно работает, а не ждёт
   голову `rx_queue` или крипту;
2. **съёмная доля** работы диспетчера (`X` минус `counter_validate`,
   `endpoint` и `prev_queue_peek` из P0 плюс `Y`; `tx` сюда не входит, это
   отдельное условие 6) даёт по бюджету `1 / (1 - доля) ≥ 1.5`. Если доля
   меньше ~33%, цель +50% недостижима;
3. crypto-воркеры на CPU 0–2 загружены **≤ 60%**, очередь decrypt не растёт;
4. есть **минимум `K` ядер с запасом ≥ 30%**, не считая CPU приёма сокета
   и iperf3; суммарная загрузка CPU 0–2 (workqueue) и CPU iperf3 ≤ 80%.
   На 6 vCPU это означает `K<=4`; для `K>4` нужен стенд ≥ 8 vCPU или явное
   решение о переподписке с пометкой в отчёте;
5. softirq на CPU приёма сокета **≤ 70%**; `time_squeeze` и `dropped` не
   растут систематически;
6. **у отправителя есть запас ≥ ~3.3 Гбит/с** для целевой ячейки: TX-воркер
   и crypto-воркеры шифрования не насыщены, `run_delay` низкий. Без этого
   +50% на одном пире недостижимы независимо от RX.

Условие 6 — обязательное и самое дешёвое: цель end-to-end, а TX-путь пира
остаётся последовательным. P0 профилировал только приёмную сторону и
`napi/uwgb0-0` (ACK), а не TX-воркер и шифрование. Если запаса нет, S3 не
реализуется: сначала шардируется TX или меняется цель на агрегат нескольких
пиров.

Если условия не выполнены — S3 не реализуется. Сначала лечится фактическое
узкое место: RPS/очереди veth, cpumask crypto-воркеров, приём сокета или
сторона отправителя. Это дешевле, чем ещё один эксперимент на +6%.

### 9.3. Результат

Отчёт `.local/handover/artifacts/S3-GATE-2026-11-*.md` (вне git):
таблица «поток/CPU → загрузка», `runtime`/`run_delay`, доля poll, съёмная
доля и оценка ускорения, запас TX-пути отправителя, вердикт PASS/FAIL.
При FAIL — какое звено насыщено и что делать вместо S3 (RPS/veth, cpumask
crypto, приём сокета, TX-шардирование или переход на агрегат пиров).

### 9.4. Результат гейта 2026-11-18

- Чистый throughput: obf0 2009.7 Мбит/с (медиана, final4 −2.3%), obf1
  1714.9 (−8.6%; база obf1 недействительна).
- Диспетчер `napi/uwgb1-0`: `runtime` 8.48 с / 30 с = **28%**, `run_delay`
  4.49 с = 15%. Для гейта нужно ≥85%.
- CPU1: **100%** (62.9% softirq + 36.6% sys), остальные ядра 30–70% простоя.
- NET_RX за 30 с: 3.92 млн на CPU1, 0.22 млн на CPU2, 0 на CPU0/3/4/5.
- crypto workqueue: ~5.6% на отправку и ~5.9% на приём; TX не насыщен.
- `softnet_stat`: дропов и роста `time_squeeze` нет.

Вердикт: **FAIL**. Съёмная доля ~19% одного CPU, потолок ~1.23×, а не
1.5×. Насыщен входной softirq veth, а не NAPI. Следующие кандидаты:
развести crypto и softirq по CPU, A/B RPS/XPS на veth, UDP GRO/батчирование
на сокете, несколько внешних UDP-потоков на пира, либо принять потолок
одного пира и целить в агрегат.

## 10. План реализации

### Этап 1. Гейт

- Собрать `master` non-debug, снять профиль по 9.1–9.3, включая TX.
- При FAIL — остановиться и зафиксировать вывод в TODO/PERFORMANCE.

### Этап 2. Рефакторинг без изменения поведения

- Выделить `gate` и `finish` из `uwg_packet_consume_data_done`.
- `K=1` вызывает обе части подряд, сохраняя все инварианты из 4.4.
- контракт владения `gate`/`finish`/`deliver` (`TAKEN`/`RETURNED`),
  `BUILD_BUG_ON` на `packet_cb`, `atomic64_t rx_bytes` и `atomic64_read`
  в netlink.
- Тесты: `selftest`, `netns.sh`, `k-sanity.sh` — поведение не меняется.
- Коммит: `refactor(kernel): разделить подготовку и завершение RX-пакета`.

### Этап 2.5. A/B `master` против рефакторинга при `K=1`

- 5 раундов ABBA, `3c c10` obf0/obf1, 3 повтора, база — `master`.
- Допуск — измеренный шум; если рефакторинг стоит больше, он чинится до
  включения шардов.
- Иначе контроль `K=1` внутри S3 будет сравниваться не с `master`, а с
  уже подорожавшим путём.

### Этап 3. Каркас шардов

- `rx_path_shard.c/h`: структуры, init/uninit, poll, sysfs, счётчики,
  `module_param rx_path_shards` (default 1).
- `K=1` — старый путь без кольца.
- `K>1` пока не включается или включается только для теста.
- Selftest хэша: TCP/UDP/ICMP, IPv4/IPv6, фрагменты, стабильность.
- `k-sanity.sh`: `K=3 → 3`, `K=100 → min(16, nCPU)`, `K=0 → 1`;
  `dmesg` без WARN.
- Коммит: `feat(kernel): добавить пул шардов полного пути пира`.

### Этап 4a. Fail-fast пилот

- Только TCP, но с уже включённым хэшем TCP в decrypt-воркере и
  `READ_ONCE(rx_path_shards_num) > 1`; иначе все пакеты уйдут в шард 0 и
  пилот ничего не покажет.
- `K=2`, `3c c10` obf0, 1–2 ячейки, 1–3 повтора.
- Проверить: нет WARN, `ring_full` близок к нулю, модель гейта
  подтверждается по CPU, throughput не падает.
- При провале — не переходить к 4b, зафиксировать причину.
- Это защита от повторения S2: функциональные тесты и полная матрица не
  должны идти раньше дешёвой проверки эффекта.

### Этап 4b. Полное включение

- Расширение хэша на UDP/ICMP и фрагменты, `unparsed`/`fragmented`,
  счётчики `dishonest_size/type`.
- Передача владения, `pending`/`napi_schedule`, дренаж, `is_dead`.
- Атомарная статистика, счётчики дропов по причинам.
- Тесты:
  - `netns.sh` `K=1/2/4`, `k-sanity.sh`;
  - порядок: нумерованные пакеты одного потока, проверка монотонности;
  - `nstat` OFO/DSACK в K=1 против K=4;
  - стресс «1 поток + CPU-хаг на ядрах шардов», 10 мин, без провалов;
  - 100 циклов churn пиров и `rmmod` под нагрузкой;
  - `kmemleak`, дельты `skbuff_head_cache`/`skbuff_fclone_cache`.
- Коммит: `feat(kernel): шардировать полный путь RX после replay`.

### Этап 5. Замеры

- Матрица по 11.1, база `K=1` в том же прогоне.
- 5 раундов ABBA для целевой и контрольных ячеек; 3 раунда — только для
  скрининга промежуточных `K`.
- Пост-профиль: `perf` по диспетчеру и шардам, требование «≥80% доставки
  уехало в шарды» и диспетчер разгрузился до модельного уровня.
- Отчёт `.local/handover/artifacts/S3-RESULTS-2026-11-*.md` (вне git).

### Этап 6. Решение и документация

- Решение принимается по 1.2: цель +50%, минимум для слияния +30%.
- **Default `K` фиксируется до слияния.** Базовый вариант — `default=1`
  (opt-in); если `K=2` рекомендуется, это отдельное решение с проверкой
  `1c`/`3c c1` на default.
- Иначе — ветка остаётся экспериментом, обновляются TODO/PERFORMANCE.
- Убрать расхождения S2 в TODO и PEER-SHARDING.

## 11. План проверки

### 11.1. Матрица

| Ось | Значения |
|---|---|
| `K` | 1 (контроль), 2, 3; 4 — если гейт подтвердил ресурсы; 6 — только на стенде ≥ 8 vCPU |
| Ячейки | `3c c10` (цель), `3c c1`, `1c c1`, `1c c10` (контроли — в пределах шума) |
| Профиль | obf0, obf1 |
| Повторы | 3 раунда скрининга; 5 раундов ABBA для решения |
| Пиры | 1 (основное); 4 — guardrail (потоки/утечки/WARN) плюс одна диагностическая ячейка `4 пира × K=4 × 3c c10 obf0` для `producer_lock`: `ring_full`, `schedstat.run_delay` шлюзов, `%sys` в `perf` |
| TCP | `-l 1420` |
| UDP | `3c c10` и `1c c1`, `UDP_RATE=1G` и без лимита |

`K=3` естественен для стенда с workqueue 0–2. `1c c10` важен: workqueue
прибит к CPU 0, а шарды не прибиты, поэтому там возможен неожиданный
эффект. Порядок ячеек рандомизируется, между ячейками — cooldown; в отчёт
пишется длительность прогона.

### 11.2. Что снимать

- throughput `sum_received`; ретрансмиты **на Гбит** и на пакет, а не
  абсолют;
- дропы по причинам из sysfs: `replay`, `ring_full`, `is_dead`,
  `allowedips`, `unparsed`, `fragmented`, `dishonest_size`, `dishonest_type`,
  `trim_fail`; `keepalive` — отдельной строкой, это не дроп; плюс
  `rx_dropped`/`rx_errors`;
- TCP-стек (`nstat -az` до/после): `TcpExtTCPOFOQueue`,
  `TcpExtTCPDSACKRecv`, `TCPTimeouts`, `TCPSpuriousRTOs`,
  `TCPSynRetrans`, `TCPBacklogDrop`; `ss -ti` для retrans/OOO;
- UDP: `nstat -n`, `UdpRcvbufErrors`, `UdpInErrors`, `ss -uanm`; потери
  туннеля отделяются от `RcvbufErrors` только при нулевых счётчиках модуля;
- per-shard `packets/bytes/ring_full`, max/mean, распределение по CPU
  (`ps -eLo psr,comm`): шарды занимают не меньше `min(K, доступных)` разных
  CPU, диспетчер не делит CPU с самым горячим шардом; фактическое
  размещение — в отчёт;
- число NAPI-потоков: `пиры + (K>1 ? K : 0)`, не `пиры × K`; per-CPU
  workqueue-потоки (`uwg-crypt-*`, `uwg-kex-*`) считаются отдельно;
- CPU по потокам, `schedstat`, `softnet_stat`, `perf` по диспетчеру и
  шардам;
- p50/p99 задержки туннеля под нагрузкой целевой ячейки: не меньше 10 000
  отсчётов ICMP-ping; TCP RTT — отдельно через `ss -ti`/`tcprtt`; p99.9 —
  ориентир при ≥100 000 отсчётов или не заявляется; UDP-джиттер отдельно;
- память: `slabtop`, `skbuff_head_cache`, `skbuff_fclone_cache`, число
  kthread'ов, `kmemleak`; сверка «сумма per-shard bytes + handshake bytes =
  netlink `rx_bytes` = `ip -s link`» с допуском на keepalive/служебные;
- `dmesg` на каждую ячейку.

### 11.3. Стоп-условия и решение

- ретрансмиты на Гбит более чем в 2 раза выше `K=1`;
- p99 хуже более чем на 20%;
- контрольная ячейка хуже `K=1` больше чем на измеренный шум (95% CI
  парных дельт), а не фиксированные −5%;
- `WARN`/`BUG`/утечка потоков или skb;
- `ring_full > 0` в целевой ячейке;
- `fragmented > 0` в целевых ячейках; `unparsed > 0.1%` пакетов;
  `allowedips_drop`/`dishonest_*` выше `K=1` больше чем на шум;
- UDP: потери или джиттер хуже `K=1` больше чем на шум;
- пост-профиль показывает, что в шарды уехало меньше 80% доставки;
- все шарды сели на один CPU или диспетчер делит CPU с самым горячим
  шардом; результат для этого `K` переснимается.

При срабатывании — откат конкретного `K` или всей ветки. Одна
предзарегистрированная правка (размер кольца или `K`) допустима только с
полным перепрогоном; подкрутка порогов после факта запрещена.

## 12. Риски

1. **Диспетчер останется бутылкой.** Replay, endpoint, hash и постановка в
   кольцо всё ещё последовательны. Если гейт покажет высокую их долю,
   выигрыш ограничен. Митигация: профиль, `K` и размер кольца по замерам.
   Сюда же входит head-of-line blocking на голове `rx_queue`: один
   медленный decrypt стопорит все потоки пира.
2. **GRO по шардам.** Каждый шард агрегирует только свои потоки. При
   корректном хэше поток не размазывается, но кросс-потоковые агрегаты
   исчезают. Следить за p99 и ретрансмитами, а не только throughput.
3. **Неравномерность потоков.** 10 TCP-потоков на 4 шарда дают перекос;
   `ring_full` концентрируется на горячем шарде (S2: 0/1/3908/0). Лечится
   размером кольца, числом шардов и, при необходимости, flow-таблицей.
4. **Refcount-контеншен.** 3 `peer_get/put` и 1 `keypair_get/put` на
   DATA-пакет на одних cacheline'ах. При K потоках bouncing растёт,
   линейного масштабирования не будет. Это ожидаемая цена.
5. **Жизненный цикл.** Новое поколение ссылок в кольцах. Ошибка даёт UAF или
   утечку. Обязательны дренаж, `WARN_ON(!empty)`, `is_dead` и порядок
   `peer`/`keypair` put. Отдельно: `napi_gro_receive` затирает `skb->cb`,
   поэтому все указатели и длина снимаются до GRO.
6. **Потеря пробуждения.** `pending` + проверка кольца после
   `napi_complete_done`; без `atomic_xchg`/`smp_mb` пакет может застрять до
   следующего пакета.
7. **Порядок кросс-потоковых пакетов.** Для нефрагментированного TCP-потока
   сохраняется; для UDP/QUIC допустим, но при чувствительных приложениях
   может ухудшить jitter. UDP-ячейка — обязательный контроль.
8. **Потоки и память.** `K` на устройство; при многих устройствах и `K=16`
   это заметно. Ограничение `UWG_MAX_RX_PATH_SHARDS` и `K <= nCPU`.
9. **CPU-привязка.** Публичного API привязки threaded NAPI к CPU нет;
   шарды распределяет планировщик. Ожидать «ровно один шард на CPU»
   нельзя; размещение проверяется и фиксируется в отчёте.
10. **Сложность отката.** Ветка должна быть изолирована: `K=1` — старый путь,
    удаление шардов не меняет семантику `master`.
11. **Отправитель.** TX-путь одного пира остаётся последовательным. Если он
    не держит ~3.3 Гбит/с, цель +50% недостижима никаким RX-шардированием;
    поэтому TX-профиль — часть гейта.
12. **Контеншен `producer_lock`.** При нескольких пирах все шлюзы пишут в
    одно кольцо через общий `ptr_ring.producer_lock`. Это точка контеншена
    на горячем пути; проверяется на 4 пирах.
13. **Отложенные allowedips.** Пока пакет лежит в кольце, удаление
    allowed-IP пира или `uwg_allowedips_free` ретроактивно дропает уже
    принятый пакет. В `master` окно короче; поведение допустимое, но это
    изменение семантики.
14. **Дрейф базы.** Стенд даёт 1835–2056 Мбит/с в `3c c10` в зависимости от
    прогона. Без проверки базы `K=1` на ±5% от final4 абсолютный пол
    3090/2810 превращается в другое требование; поэтому база проверяется
    до интерпретации результата.
15. **Default `K`.** При `default=1` выигрыш opt-in, при `default>1`
    рискуют контроли `1c`/`3c c1`. Решение фиксируется до слияния, а не
    остаётся открытым вопросом.

## 13. Что не делать

- Не двигать `counter_validate` в шарды: дублирование окна ломает
  anti-replay, общий лок — конкуренция.
- Не резать до `rx_queue`: decrypt-воркеры завершаются произвольно, порядок
  TCP теряется.
- Не делать fallback в другой шард или синхронную доставку при переполнении:
  это ломает порядок потока.
- Не отключать threaded NAPI, не повторять P0-3/P0-4 и TX-коалесинг без
  новых замеров.
- Не включать `K>1` по умолчанию до прохождения критериев 1.2.

## 14. Решения и открытые вопросы

Уже решено в документе:

- `default=1`, `K` фиксируется при создании устройства (§4.1);
- `peer->napi` при `K>1` остаётся шлюзом без GRO (§4.2);
- UDP и ICMP хэшируются, а не отправляются в шард 0 (§4.5);
- фрагментированный TCP — вне гарантии порядка, мини-таблица не входит в
  первый прототип (§4.5);
- `K=1` — старый путь без кольца и без аллокаций (§4.4, §6.1).

Открытые вопросы:

1. Какой `K` рекомендуется по умолчанию — `1` (opt-in) или `2` — по
   результатам `1c c1`/`3c c1`; фиксируется до слияния.
2. Нужен ли per-flow лимит и flow-таблица для борьбы с перекосом, или
   достаточно хэша и кольца?
3. Нужна ли flow-таблица с TTL для QUIC migration и смены адреса, чтобы
   поток не переезжал между шардами на лету?

## 15. Ссылки на код

| Что | Где |
|---|---|
| RX-путь DATA | `src/receive.c:527-688` |
| replay | `src/receive.c:381-417`, `src/noise.h:18-22` |
| `PACKET_CB`/`PACKET_PEER` | `src/queueing.h:62-74` |
| `rx_queue` | `src/queueing.c:121-177` |
| крипто-очереди | `src/queueing.h:183-233`, `src/receive.c:588-608` |
| завершение RX | `src/receive.c:421-525` |
| NAPI пира | `src/peer.c:57-59`, `src/peer.c:95-151` |
| endpoint | `src/socket.c:275-338` |
| таймеры | `src/timers.c:32-41`, `src/timers.c:168-267` |
| allowedips | `src/allowedips.c:127-147` |
| устройство | `src/device.c:244-276`, `src/device.c:322-420` |
| S2-реализация | ветка `kernel/rx-shards`, `src/rx_shard.c` |
