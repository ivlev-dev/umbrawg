# Стенд замера пропускной способности UmbraWG

Изолированный стенд: два netns (`bn0`, `bn1`), veth-пара `bveth0`/`bveth1`,
в каждом ns — интерфейс `uwgb0`/`uwgb1` (kernel-модуль `umbrawg`, `amneziawg`
или userspace `umbrawg`/`amneziawg-go`). Нагрузка — `iperf3`, приёмник
закреплён на отдельном ядре (`IPERF_CPU`, по умолчанию 3).

## Быстрый старт

```bash
SMOKE=1 DURATION=1 IMPL_LIST="kernel-umbrawg" bash bench.sh
PLAN_ONLY=1 SMOKE=1 FORCE=1 bash bench.sh            # план без трафика
PLAN_ONLY=1 SMOKE=1 FORCE=1 FEC_LIST="off adaptive 2:1 8:2" bash bench.sh  # план FEC-оси
IMPL_LIST="kernel-umbrawg kernel-amneziawg" MODE_LIST="1c 3c" REPEATS=5 bash bench.sh
PROTO_LIST=udp UDP_RATE_LIST="1G 0" CONNS_LIST="1 10" bash bench.sh
python3 bench-report.py results-20261116-120000.csv --md report.md --agg agg.csv
```

## Тесты расширения FEC

`bench/wire-ext.sh`, `bench/ext-matrix.sh` и `bench/ext-tests.sh` проверяют
расширение `FEC` (BBR удалён в 0.5.0) на той же топологии, что и остальной стенд: два netns,
veth, kernel-модуль `umbrawg`; вторая сторона — Rust-демон (`IMPL=rust`),
ещё один kernel-интерфейс (`IMPL=kernel`) или два Rust-демона без модуля
(`IMPL=rust2`). `wire-ext.sh` делает один прогон (ping, TCP, UDP, pcap),
`ext-matrix.sh` прогоняет матрицу и собирает CSV, `ext-tests.sh` — набор
interop-кейсов с порогами и кодом возврата.

Нужны root, собранные `uwg` и демон `umbrawg` (для `IMPL=rust`/`rust2`), а
также `umbrawg.ko` (для `IMPL=rust`/`kernel`). Пути переопределяются через
`KO`, `UWG`, `RUST`. Стенд
эксклюзивный: скрипт выгружает `umbrawg`, создаёт netns `xwg0`/`xwg1` и по
окончании удаляет их; параллельные замеры недостоверны.

### Один прогон

```bash
sudo IMPL=kernel KFEC=2:1 DUR=4 bash bench/wire-ext.sh
sudo IMPL=rust KFEC=adaptive RFEC=adaptive DUR=4 NETEM_LOSS=2 bash bench/wire-ext.sh
sudo IMPL=rust2 KFEC=2:1 RFEC=2:1 DUR=4 NETEM_LOSS=2 bash bench/wire-ext.sh
sudo IMPL=kernel KFEC=8:2 NETEM_LOSS=2 NETEM_BOTH=1 TUNMTU=1420 bash bench/wire-ext.sh
sudo IMPL=kernel KFEC=2:1 NETEM_RATE=100mbit NETEM_DELAY=10 KEEP=1 bash bench/wire-ext.sh
```

Строка результата (её же разбирает матрица):

```
RESULT tag=smoke impl=kernel dir=k0 fec=2:1 loss=2 tcp_mbit=663.0 udp_mbit=399.9 udp_loss=0.2 ping_loss=0 frag=0 result=OK
```

`result`: `OK`, `FAIL_LINK` (не поднялся туннель), `FAIL_TCP`, `FAIL_UDP`.
Артефакты `OUT.*` (`-tcp.json`, `-udp.json`, `.pcap`, логи iperf3) остаются
в `/tmp`; `KEEP=1` оставляет netns, модуль и демон для разбора.

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `IMPL` | rust | `rust` — kernel↔Rust, `rust2` — Rust↔Rust без модуля, `kernel` — kernel↔kernel |
| `DIR` | k0 | на какой стороне kernel: `k0` (ns0) или `k1` (ns1) |
| `KFEC` / `RFEC` | off | FEC kernel-стороны / Rust-стороны: `off`, `adaptive`, `K:M` |
| `NETEM_LOSS` | 0 | потери в % на underlay |
| `NETEM_DELAY` | 0 | задержка netem (мс или с единицей, напр. `10ms`) |
| `NETEM_RATE` | пусто | полоса netem в единицах tc, напр. `100mbit` |
| `NETEM_BOTH` | 1 | 1 — netem на обе стороны, 0 — только egress kernel-стороны |
| `UMTU` / `UNDERLAY_MTU` | 9000 | MTU veth |
| `TUNMTU` | 1420 | MTU туннельных интерфейсов |
| `DUR` | 4 | длительность TCP и UDP по отдельности, с |
| `UDP_RATE` | 400M | предложенная скорость UDP |
| `FEC_SHARD`, `ACK_INTERVAL` | пусто | необязательные env Rust-демона (`UMBRAWG_FEC_SHARD`, `UMBRAWG_ACK_INTERVAL`) |
| `TAG` | ext | метка прогона |
| `SKIP_PING` | 0 | 1 — не измерять ping (handshake-проверка остаётся) |
| `KEEP` | 0 | 1 — не удалять netns/модуль/демоны после прогона |
| `KO`, `UWG`, `RUST` | пути репозитория | бинарники стенда |
| `PORT0`, `PORT1`, `IPERF_PORT` | 53920, 53921, 5291 | underlay-порты и порт iperf3 |

В mixed-режиме (`IMPL=rust`) FEC задаётся отдельно для каждой стороны.
`RFEC` по умолчанию повторяет `KFEC`; для kernel↔kernel
значение `RFEC` игнорируется (обе стороны используют `KFEC`).
`FEC` работает как алиас `KFEC`. BBR удалён в 0.5.0.

### Rust↔Rust без kernel-модуля (`IMPL=rust2`)

`IMPL=rust2` поднимает два userspace-демона `umbrawg` — по одному в каждом
netns (`xwg0`/`xwg1`) — и не загружает `umbrawg.ko` вовсе. Каждый демон
создаёт свой TUN (`uwg0`/`uwg1`), получает собственный конфиг
(`PrivateKey`, `PublicKey`, `ListenPort`, `Endpoint`, `AllowedIPs`,
`PersistentKeepalive`) и собственные underlay-порты `PORT0`/`PORT1`.
Расширение включается через env каждого процесса: сторона в `xwg0` получает
`UMBRAWG_FEC=FEC_SIDE0`, сторона в `xwg1` —
`FEC_SIDE1`; при `DIR=k0` это `KFEC` и `RFEC`
соответственно. Секция `FEC` в конфиг не пишется, чтобы env не
перетирался `setconf`. Ping, TCP, UDP, pcap, `RESULT`-строка и cleanup —
общие с остальными режимами; по завершении убиваются оба демона, сокеты и
netns. `KO` для этого режима не нужен, `UWG` (setconf) и `RUST` — нужны.

```bash
sudo IMPL=rust2 KFEC=2:1 RFEC=2:1 DUR=4 bash bench/wire-ext.sh
sudo IMPL=rust2 KFEC=2:1 RFEC=2:1 NETEM_LOSS=2 NETEM_BOTH=1 bash bench/wire-ext.sh
```

### Матрица

```bash
PLAN_ONLY=1 bash bench/ext-matrix.sh          # только план, без root и трафика
sudo bash bench/ext-matrix.sh                # 32 прогона
sudo DUR=2 FEC_LIST="off 2:1 adaptive" bash bench/ext-matrix.sh
sudo LOSS_LIST="0 2 5" NETEM_RATE=100mbit bash bench/ext-matrix.sh
sudo DIR_LIST="k0 k1" IMPL_LIST=kernel bash bench/ext-matrix.sh
sudo IMPL_LIST=rust2 FEC_LIST="off 2:1 8:2 adaptive" LOSS_LIST="0 2" bash bench/ext-matrix.sh
```

| Ось | Значения по умолчанию | Что проверяет |
|---|---|---|
| `IMPL_LIST` | `rust kernel` | mixed kernel↔Rust и kernel↔kernel; `rust2` — Rust↔Rust без модуля (не требует `umbrawg.ko`) |
| `FEC_LIST` | `off 2:1 8:2 adaptive` | цена fixed-режимов и поведение adaptive |
| `LOSS_LIST` | `0 2` | чистый канал и 2% потерь |
| `DIR_LIST` | `k0` | сторона kernel; `k0 k1` для проверки симметрии |

`adaptive` включается по входящим потерям >1% после прогрева 1024 пакетов,
поэтому для него нужны потери в обе стороны: `NETEM_BOTH=1` (значение по
умолчанию) или потери на стороне Rust-пира. При односторонних потерях
сторона с чистым входящим потоком останется в legacy.

CSV пишется в `bench/tmp/ext-matrix-<RUN_ID>.csv`:

```
tag,impl,dir,fec,loss,tcp_mbit,udp_mbit,udp_loss,ping_loss,frag,result
```

`tcp_mbit` — goodput TCP; `udp_mbit`/`udp_loss` — принятая скорость и потери
UDP при `UDP_RATE`; `ping_loss` — потери ICMP (`SKIP` при `SKIP_PING=1`);
`frag` — число IP-фрагментов в pcap (`-`, если tcpdump недоступен); `result`
— `OK` или причина отказа. Логи прогонов лежат в
`bench/tmp/ext-matrix-<RUN_ID>/`. В конце печатается сводка по
`impl/fec/loss` (медианы) и списки фрагментированных и упавших прогонов.

### Interop-проверки (ext-tests.sh)

`bench/ext-tests.sh` — готовый набор из восьми interop-кейсов с порогами:
каждый кейс вызывает `wire-ext.sh` (один или два раза), разбирает его
`RESULT`-строку и печатает `PASS`/`FAIL` с причиной. Код возврата: `0` — все
кейсы прошли, `1` — есть `FAIL`, `2` — ошибка конфигурации (неизвестный кейс,
нет root, нет `wire-ext.sh`). Скрипт не заменяет матрицу: он отвечает на
вопрос «не сломали ли расширение», а не «насколько быстро».

```bash
PLAN_ONLY=1 bash bench/ext-tests.sh              # план без root и трафика
sudo bash bench/ext-tests.sh                     # все 8 кейсов, DUR=2
sudo DUR=3 bash bench/ext-tests.sh               # длиннее и стабильнее
sudo CASES="mixed-fec21 profile-mismatch" bash bench/ext-tests.sh
sudo CASES="rust2-fec21" bash bench/ext-tests.sh
sudo FAILFAST=1 KEEP=1 CASES="mixed-fec21" bash bench/ext-tests.sh
```

| Кейс | Что запускается | Условия PASS |
|---|---|---|
| `mixed-fec21` | `IMPL=rust`, `2:1` с обеих сторон, loss 2% в обе стороны | `result=OK`, TCP>0, `udp_loss<1`, `ping_loss=0`, `frag=0` |
| `kernel-fec21` | `IMPL=kernel`, `2:1`, loss 2% в обе стороны | то же: FEC восстанавливает потери в kernel↔kernel |
| `rust2-fec21` | `IMPL=rust2`, `2:1` с обеих сторон, loss 2% в обе стороны | `result=OK`, TCP>0, `udp_loss<1`, `ping_loss` в пределах lossy-порога, `frag=0` |
| `profile-mismatch` | kernel `2:1`, Rust `8:2`, loss 2% | TCP>0, `udp_loss` в `[1..4]`, `ping_loss=0`: несовпадение профилей уходит в legacy без чёрной дыры |
| `adaptive-clean` | два прогона: `off` и `adaptive`, loss 0 | `udp_loss<0.2`, `tcp_adaptive >= (1-0.12)*tcp_off` — adaptive на чистом канале не включается и не платит overhead |
| `clean-fec21` | `IMPL=kernel`, `2:1`, loss 0 | TCP ≥ 1000 Мбит/с на 9k underlay, `udp_loss<0.2` |

Пороги вынесены в переменные: `MIN_TCP_CLEAN_FEC` (1000),
`MAX_UDP_LOSS_FEC` (1), `MAX_UDP_LOSS_CLEAN` (0.2),
`MAX_PING_LOSS_LOSSY` (20), `MATCH_UDP_LOSS_MIN`/`MATCH_UDP_LOSS_MAX` (1/4),
`ADAPTIVE_TCP_TOL` (0.12).
Пороги про Мбит/с зависят от машины: на слабом или занятом стенде их
опускают, а не «подгоняют» результат.

Формат вывода:

```
[ext-tests] [1/9] run ...-mixed-fec21 impl=rust fec=2:1/2:1 loss=2
[ext-tests] [1/9] done 14s result=OK tcp=663.0 udp=399.9 udp_loss=0.2 ping=0 frag=0
[ext-tests] CASE mixed-fec21 PASS  14s  info=[result=OK tcp=663.0>0 udp_loss=0.2<1 ping_loss=0==0 frag=0==0]
[ext-tests] CASE rust2-fec21 PASS  12s  info=[result=OK tcp=512.0>0 udp_loss=0.1<1 ping_loss=0<=20 frag=0==0]
[ext-tests] done: cases=8/8 pass=7 fail=1 runs=9/9 in 120s
[ext-tests] failed cases: (none)
```

`info` — фактические значения и проверенные границы, `failed` — что именно
не сошлось. `frag=SKIP` в `info` означает, что `tcpdump` недоступен и
фрагментацию проверить нельзя (не ошибка); `result=FAIL_*` — `wire-ext.sh` не
поднял туннель или уронил iperf3. Логи и артефакты прогонов лежат в
`bench/tmp/ext-tests-<RUN_ID>/<tag>.log` и `<tag>-wire.*`.

Переменные: `CASES` (список кейсов через пробел, порядок сохраняется), `DUR`
(2), `DIR`, `UMTU`, `TUNMTU`, `NETEM_BOTH`, `UDP_RATE`, `SKIP_PING`, `KEEP`,
`FAILFAST`, `RUN_ID`/`RUN_TAG`, `LOG_DIR`, `WIRE`, плюс пути стенда `KO`,
`UWG`, `RUST` (пробрасываются в `wire-ext.sh`). `KEEP=1` оставляет netns,
модуль и демоны после первого же прогона, поэтому следующие прогоны упадут —
сочетайте его с `CASES`.

**Время.** Девять прогонов (восемь кейсов, `adaptive-clean` делает два)
при `DUR=2` — около 2–3 минут, при `DUR=3` — около 3–4 минут (плюс
настройка ≈9 с на прогон). `PLAN_ONLY=1` печатает кейсы,
команды, число прогонов и оценку времени, не требуя root.

**Новый кейс.** Добавьте имя в `known_case`, число прогонов в `runs_of`,
функцию `case_<имя_через_подчёркивания>` (она вызывает `run_wire tag impl
kfec rfec loss` и проверки `chk_cmp`/`chk_ping`/`chk_frag`), строку
в `CASES` по умолчанию, команду в `print_plan` и строку в таблицу выше.
`run_wire` заполняет `R_TCP`, `R_UDP`, `R_UDPLOSS`, `R_PING`, `R_FRAG`,
`R_RESULT`; `chk_cmp` добавляет проверку в `info`/`failed` и возвращает
ненулевой код при провале.

### Как читать результат

- `loss=0`: `off` и `adaptive` должны совпадать — adaptive на чистом канале не
  активен. Fixed `2:1`/`8:2` ниже по TCP примерно на overhead `k+m`.
- `loss=2`: у `off` `udp_loss` около 2%; fixed и adaptive FEC должны её
  снизить. Adaptive включается только при потерях в обе стороны.
- `frag>0` при `TUNMTU`, близком к underlay MTU, означает, что FEC-шарды или
  обфускация вышли за MTU.

**Время.** Один прогон — это два замера по `DUR` плюс настройка и рукопожатие;
матрица по умолчанию (32 ячейки, `DUR=3`) идёт около 7–10 минут, с `DUR=4` и
перезагрузкой модуля — дольше. Перед длинным прогоном всегда смотрите
`PLAN_ONLY=1`.

## Память (mem-matrix.sh)

`bench/mem-matrix.sh` сравнивает потребление памяти четырёх реализаций на
отдельной топологии: два netns `mem0`/`mem1`, veth `mveth0`/`mveth1`,
интерфейсы `uwgm0`/`uwgm1`, underlay-порты `54820`/`54821` и iperf3-порт
`5401`. Стенд эксклюзивный: скрипт берёт тот же flock, что и `bench.sh`, и
отказывается стартовать при чужих модулях, netns
(`bn0`/`bn1`/`mem0`/`mem1`/`xwg0`/`xwg1`), `iperf3` или load average выше
`IDLE_LOAD_MAX` (обход — `FORCE=1`).

```bash
PLAN_ONLY=1 bash bench/mem-matrix.sh
sudo IMPL_LIST="kernel-umbrawg rust" FEC_LIST="off 2:1" PEERS_LIST="1 16" \
     LOAD_LIST=idle OBF_LIST=0 REPEATS=1 bash bench/mem-matrix.sh
sudo IMPL_LIST=go PEERS_LIST=4 LOAD_LIST="idle tcp" bash bench/mem-matrix.sh
```

По умолчанию матрица — 240 прогонов (60 ячеек × 2 повтора × idle/tcp); при
`RUN=5 SETTLE=2` это около 20 минут. Перед длинным прогоном смотрите
`PLAN_ONLY=1`.

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `IMPL_LIST` | `kernel-umbrawg kernel-amneziawg rust go` | реализации |
| `FEC_LIST` | `off adaptive 2:1 8:2` | FEC для `kernel-umbrawg`/`rust`; у AWG/go всегда `none` |
| `PEERS_LIST` | `1 4 16` | пиров на устройство (включая endpoint-пира) |
| `LOAD_LIST` | `idle tcp` | простой или TCP-нагрузка через iperf3 |
| `OBF_LIST` | `0 1` | профиль обфускации из `OBF` |
| `REPEATS` | 2 | повторов каждой ячейки |
| `SETTLE` | 2 | пауза после поднятия туннеля перед снятием, с |
| `RUN` | 5 | длительность TCP-нагрузки, с |
| `UNDERLAY_MTU` / `TUN_MTU` | 9000 / 1420 | MTU veth и туннеля |
| `FORCE` / `IDLE_LOAD_MAX` | 0 / 1.0 | обход проверки занятости |
| `UWG`, `DAEMON`, `GO_BASELINE`, `AWG`, `MODDIR`, `OBF` | пути репозитория | бинарники и профиль |
| `OUT`, `DIAG`, `LOG_DIR`, `RUN_ID` | `bench/tmp/mem-*` | артефакты |

FEC применяется как в `wire-ext.sh`: для `rust` — env `UMBRAWG_FEC` и
`FEC =` в конфиге, для `kernel-umbrawg` — `FEC =` и
`uwg set <if> fec ...` после `setconf`. У AWG/go FEC нет, поэтому `FEC_LIST`
не размножает их строки: в CSV у них `fec=none`.

### Метрики

Для userspace (`rust`, `go`) после `SETTLE` и во время iperf3 снимаются
`/proc/<pid>/status` (`VmRSS`, `VmHWM`) и `/proc/<pid>/smaps_rollup`
(`Pss`, `Private_Dirty`) для обоих демонов. В CSV — сумма и per-process;
HWM, Private_Dirty и разбивка по pid идут в diag.

Для kernel (`kernel-umbrawg`, `kernel-amneziawg`) снимаются `/proc/meminfo`
(`Slab`, `SUnreclaim`, `MemAvailable`) и `/proc/slabinfo` в точках:

1. `pre_module` — до загрузки модуля;
2. `base_pre_ifaces` — после загрузки, до создания интерфейсов (база);
3. `ifaces_only` — после создания интерфейсов, до пиров;
4. `row_idle` / `row_tcp` — после `SETTLE` или во время iperf3.

`slab_delta_kb` = Δ`Slab` от `base_pre_ifaces` до точки замера, то есть
стоимость двух интерфейсов и N пиров; загрузка модуля в дельту не входит, её
размер и `refcnt` берутся из `lsmod`. `per_peer_kb` = `slab_delta_kb / peers`.
Для `load=tcp` точка замера — во время iperf3, поэтому в дельту попадают
транзитные skb/socket-буферы; сравнивать per-peer между реализациями надо по
`load=idle`. Изменённые кэши `/proc/slabinfo` (включая `kmalloc-*`) пишутся в
diag; приватные структуры ядра не читаются.

### CSV

`bench/tmp/mem-<RUN_ID>.csv`:

```
impl,fec,peers,load,obf,repeats,rss_kb_sum,rss_kb_per_proc,pss_kb,slab_delta_kb,per_peer_kb
```

`repeats` — номер повтора (`1..REPEATS`). Для userspace заполнены
`rss_kb_sum`, `rss_kb_per_proc` (`rss0/rss1`) и `pss_kb`; для kernel —
`slab_delta_kb` и `per_peer_kb`; неприменимые поля пустые. Текстового
`FAIL` в CSV нет: при `SETUP_FAILED`/`LOAD_FAILED` строка остаётся пустой, а
причина пишется в diag и stdout. В конце печатается сводка (медианы по
`impl/fec/peers/load/obf`) и число пустых строк. Логи ячеек, slabinfo-снимки
и `<RUN_ID>.diag` лежат в `bench/tmp/mem-<RUN_ID>/` и рядом с CSV.

### Ограничения

- **Slab-дельта шумная.** Аллокатор округляет до страниц, освобождение
  отложенное, соседние процессы дают вклад; отрицательные `slab_delta_kb` и
  `per_peer_kb` — норма, а не ошибка. Порядок величин надёжнее единиц kB.
- **RSS/PSS точнее для userspace, но не идеальны.** `VmRSS` включает общие
  страницы (libc, page cache), `Pss` делит их между процессами; оба
  показывают память, удерживаемую аллокатором/GC, а не только живые данные.
  У Go заметен GC-резерв, у Rust — арены и пулы.
- **Для kernel `load=tcp` — другая метрика.** Транзитные аллокации под
  нагрузкой не масштабируются на число пиров, поэтому `per_peer_kb` сравним
  только на `idle`.
- **Один активный peer.** Трафик идёт только через endpoint-пира, остальные
  N−1 пиров — пассивная конфигурация: их стоимость — структуры peer и
  AllowedIPs, а не буферы.
- **`lsmod size` — не память процесса.** Это размер модуля (text/data/bss),
  он не входит в `slab_delta_kb`.
- **obf=1 у go/AWG** ограничен тем, что принимает их `setconf`; заглушка
  обфускации данных у go описана в общем разделе стенда.
- **Нет CPU-пиннинга и thermal-контроля**, как в `bench.sh`: замеры памяти
  чувствительны к параллельной нагрузке, поэтому проверка занятости
  обязательна.
- Модуль `umbrawg` не переиспользуется: если он уже загружен, ячейки
  `kernel-umbrawg` пропускаются (`MODULE_ALREADY_LOADED`). `amneziawg`
  переиспользуется (`MODULE_REUSED`) и не выгружается, если был загружен до
  старта.
- По завершении trap удаляет netns, демоны, сокеты и загруженные скриптом
  модули; `POSTFLIGHT: dirty` и код 4 означают, что что-то осталось.

## Ключи и секреты

В репозитории нет рабочих ключей: `obf-params.conf` — шаблон, в котором
`PrivateKey = <PRIVATE_KEY>` и `HeaderProtectionKey = <HEADER_PROTECTION_KEY>`.
Скрипты подставляют их во время прогона через `obf_block_from_conf`
(`bench-lib.sh`), вызывая `uwg genkey`; для ручных конфигов:

```bash
uwg genkey > priv.key                 # приватный ключ
uwg pubkey < priv.key                 # публичный ключ
```

`HeaderProtectionKey` должен совпадать на обеих сторонах туннеля.
**Публично известный HP-ключ убивает обфускацию заголовков**: трафик
опознаётся по неизменному префиксу, поэтому ключ нельзя коммитить, публиковать
в отчётах или переиспользовать между стендами. Локальные файлы стенда
(`keys.env`, `.t/*.conf`, `.conf-*`) перечислены в `.gitignore`.

## Переменные

Существующий интерфейс сохранён: `IMPL_LIST`, `MODE_LIST`, `PROTO_LIST`,
`CONNS_LIST`, `LOSS_LIST`, `OBF_LIST`, `PEERS_LIST`, `DURATION`, `SMOKE`,
`RESULT`. Ниже — новое.

Пути по умолчанию выводятся из расположения `bench.sh`, без привязки к
`/root`: `RUSTDIR` — `$WORKSPACE_ROOT/umbrawg-rs` (затем `rust`), `MODDIR` —
`$WORKSPACE_ROOT/umbrawg-linux-kernel-module/src` (затем `module/src`),
`UWG` — `$REPO_ROOT/target/release/uwg` или
`$WORKSPACE_ROOT/umbrawg-tools/target/release/uwg`, `DAEMON` —
`$RUSTDIR/target/release/umbrawg`. Для монорепозитория `REPO_ROOT` и
`WORKSPACE_ROOT` совпадают с корнем; для `umbrawg-tools/bench` корень
поднимается на уровень выше. Переопределяются через `RUSTDIR`, `MODDIR`
(`MODULE_DIR`), `UWG`, `DAEMON`, `GO_BASELINE`, `OBF`.

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `REPEATS` | 3 (SMOKE: 1) | число повторов каждой ячейки |
| `UDP_RATE` | 1G | суммарная предложенная скорость UDP на всю ячейку |
| `UDP_RATE_LIST` | пусто | список скоростей UDP, переопределяет `UDP_RATE`; `0` = без лимита |
| `TUN_MTU` | 1420 | MTU туннельных интерфейсов |
| `UNDERLAY_MTU` | 9000 | MTU veth (underlay) |
| `OVERHEAD_BASE` | 80 | базовый оверхед туннеля (IPv4+UDP+WG) для MTU-guard |
| `ALLOW_FRAGMENT` | 0 | 1 — разрешить заведомо фрагментированный путь |
| `VETH_QUEUES` | `nproc` | число очередей veth (max для `numtxqueues`/`numrxqueues`) |
| `VETH_RX_Q` / `VETH_TX_Q` | `VETH_QUEUES` | сколько очередей реально включить через `ethtool -L` |
| `RPS_MASK` | off | hex-маска для `rps_cpus` на rx-очередях veth (`off` — не трогать) |
| `GSO_SEGMENTS` | пусто | `UMBRAWG_GSO_SEGMENTS` для Rust-демона (алиас `UMBRAWG_GSO_SEGMENTS` тоже читается) |
| `RUST_PARALLEL` | 0 | 1 — добавить `rust-par` (`UMBRAWG_PARALLEL_RX=1`) в список реализаций |
| `RUST_RX_SCHED` | peer | планировщик RX для `rust-par` (`UMBRAWG_RX_SCHED`) |
| `FEC` | пусто | одиночный FEC-режим; если задан, переопределяет `FEC_LIST` |
| `FEC_LIST` | off | ось FEC: `off`, `adaptive`, `K:M`; действует только на umbrawg-реализации |
| `CIPHER` | пусто | значение `Cipher =` в сгенерированных конфигах |
| `RUN_ID` | timestamp | метка прогона, пишется в CSV |
| `FORCE` | 0 | 1 — обойти проверку занятости стенда |
| `PLAN_ONLY` | 0 | 1 — напечатать план, собрать пустой отчёт и выйти без прогонов |
| `IDLE_LOAD_MAX` | 1.0 | порог load average для запуска |
| `IPERF_CPU` | 3 | ядро для iperf3 |
| `TUNNEL_CPUS_1` / `TUNNEL_CPUS_3` | 0 / 0-2 | cpu для 1c/3c (userspace taskset, kernel — workqueue cpumask) |
| `CPU_HOT_PCT` | 80 | порог «горячего» ядра для `hot_cpus` в CPU-замере |

`UDP_RATE` — это **суммарная** скорость ячейки: при `-P N` на поток
передаётся `UDP_RATE/N` (минимум 1 кбит/с). Иначе `-P 100 -b 1G` означало бы
100 Гбит/с предложенной нагрузки и бессмысленные потери.

Списки задаются явно: `IMPL_LIST=""` означает «не запускать ни одной
реализации» (полезно вместе с `PLAN_ONLY=1`), а не «взять значения по
умолчанию».

## FEC

`FEC_LIST` — ось FEC-режимов: `off`, `adaptive` или фиксированный `K:M`
(например, `2:1`, `8:2`). По умолчанию `FEC_LIST=off`: стенд явно выключает
FEC и не полагается на дефолт 0.5.0 (`adaptive`), иначе матрица была бы
невоспроизводимой. `FEC=<значение>` задаёт один режим и переопределяет
`FEC_LIST`; недопустимое значение завершает запуск с `FEC_INVALID` и кодом 6.

| impl | как применяется | `fec` в CSV и логе |
|---|---|---|
| `kernel-umbrawg` | после `uwg setconf` для `bn0`/`bn1` выполняется `uwg set <if> fec <value>`, затем `wait_tunnel` | значение |
| `rust`, `rust-par` | `UMBRAWG_FEC=<value>` в env демона при старте, плюс `uwg set <if> fec <value>` после `setconf` | значение |
| `kernel-amneziawg`, `go` | FEC не поддерживается, ось игнорируется, лишних прогонов нет | `none` |

Явный `uwg set fec` после `setconf` нужен и для Rust: `uwg setconf` в 0.5.0
отправляет `fec=adaptive`, если ключа нет в конфиге, и иначе перетирает
`UMBRAWG_FEC`. Порядок применения: `start_impl` → `setconf` → `uwg set fec` →
`wait_tunnel`. Для `kernel-amneziawg` и `go` FEC-ось не размножает ячейки: на
каждый `impl` выполняется один набор с `fec=none`.

Полная матрица:

```bash
PLAN_ONLY=1 SMOKE=1 FORCE=1 \
  IMPL_LIST="kernel-umbrawg kernel-amneziawg rust go" \
  FEC_LIST="off adaptive 2:1 8:2" bash bench.sh
sudo IMPL_LIST="kernel-umbrawg kernel-amneziawg rust go" \
  FEC_LIST="off adaptive 2:1 8:2" bash bench.sh
```

В `PLAN`-строках и в логе каждого прогона есть поле `fec=<value>`, в CSV —
колонка `fec`. `bench-report.py` читает CSV по именам колонок и `fec`
игнорирует, поэтому при нескольких режимах в одном CSV агрегат смешивает их.
Для отчёта по отдельному режиму запускайте его с `FEC=<value>` и своим
`RESULT` (например, `FEC=2:1 RESULT=results-fec21.csv`).

## Методика

1. **Повторы.** Каждая ячейка меряется `REPEATS` раз подряд; в CSV пишутся все
   прогоны (`run`, `repeat`), агрегат (`median`, `min`, `max`, `n`) — в
   `RESULT.agg.csv`, отчёт — в `RESULT.md`.
2. **Один поток vs много потоков.** Обязательны оба режима:
   `CONNS_LIST="1 10 100"`. При `-P 1` весь трафик — один UDP/TCP-поток,
   поэтому он живёт на одной RX-очереди и на одном ядре: `3c` физически не
   может масштабироваться. Вывод о масштабировании делается только по
   многопоточным ячейкам.
3. **UDP.** Режим фиксированной скорости (`UDP_RATE=1G`) — проверка «держит ли
   реализация скорость», потери пишутся в `lost_percent`. Режим без лимита
   (`UDP_RATE=0`) — это goodput при перегрузе: потери 60–90% нормальны, цифру
   нельзя называть пропускной способностью. Оба режима помечены в CSV
   (`udp_rate`, `udp_mode`).
4. **MTU-guard.** Перед запуском проверяется
   `TUN_MTU <= UNDERLAY_MTU - (OVERHEAD_BASE + S4 профиля)`; при underlay
   ≥ 9000 проверка не нужна. При 1500 и S4=28 безопасно `TUN_MTU=1380`.
   При нарушении скрипт падает с кодом 2 (обход — `ALLOW_FRAGMENT=1`).
   Дополнительно на каждой ячейке считается прирост `FragOKs`/`FragCreates`
   в обоих netns: при фрагментации пишется `FRAGMENTED` в diag и `frag>0` в CSV.
5. **Занятость стенда.** Перед запуском проверяются load average, чужие
   `iperf3`, загруженные модули, netns `bn0`/`bn1`, другие экземпляры
   `bench.sh`, плюс flock. При занятости запуск отменяется (код 3) — иначе
   замеры искажают параллельные сборки и функциональные тесты.
6. **Чистота.** Trap удаляет netns, сокеты, свои процессы iperf3, выгружает
   только те модули, которые загрузил сам, и возвращает
   `workqueue/cpumask=all`. В конце печатается `POSTFLIGHT: clean|dirty`
   (dirty → код 4). Состояние модулей/netns/iperf3 на момент старта
   запоминается, поэтому чужой `umbrawg`, чужой netns и чужой `iperf3` не
   считаются грязью.
7. **Модули.** Если `umbrawg` уже загружен, ячейка `kernel-umbrawg`
   пропускается с `MODULE_ALREADY_LOADED` (нельзя гарантировать, что это
   текущая сборка). Загруженный `amneziawg` переиспользуется с пометкой
   `MODULE_REUSED`.
8. **Загрузка CPU.** На каждый ряд iperf3 снимаются два среза `/proc/stat`
   (до и после клиента, интервал ≈ `DURATION`), дельты дают busy% по каждому
   CPU. В diag пишется строка `CPU_BUSY ...` с `per_cpu`, `hot_cpus`
   (ядра с busy ≥ `CPU_HOT_PCT`), `total` (суммарная загрузка машины) и
   `iperf_cpu`/`tunnel_cpus` для интерпретации. В CSV — колонки `cpu_hot` и
   `cpu_total`. Это позволяет отличить «упёрлись в одно ядро» от реального
   параллелизма; mpstat не требуется.

## CSV

`impl,mode,proto,conns,loss,obf,peers,mbit,extra,run,repeat,lost_percent,udp_rate,udp_mode,streams,frag,cpu_hot,cpu_total,fec`

Первые 9 колонок совместимы со старым форматом (`extra`: retransmits для TCP,
lost_percent для UDP). `mbit` — `sum_received`, то есть goodput.
`FAIL` в `mbit` — прогон не удался. `cpu_hot`/`cpu_total` — необязательные:
число ядер с busy ≥ `CPU_HOT_PCT` и суммарная busy% машины за ряд; при
недоступности `/proc/stat` там `-`. `fec` — применённый режим (`off`,
`adaptive`, `K:M`) или `none` для `kernel-amneziawg`/`go`. Старые парсеры,
читающие первые 18 колонок, не ломаются; старые CSV без `fec` читаются
`bench-report.py`, потому что он разбирает файл по именам колонок.
Старый `results.csv` (другая схема) не
перезаписывается: при несовпадении заголовка скрипт пишет в
`results-<RUN_ID>.csv`.

Diag-файл (`RESULT.diag`) дополняется строкой на каждый ряд:

```
CPU_BUSY impl=kernel-umbrawg mode=3c proto=tcp conns=1 obf=1 run=1 per_cpu=..,..,..,..,..,.. hot_cpus=2 total=63 iperf_cpu=3 tunnel_cpus=0-2
```

`per_cpu` идёт по возрастанию номера CPU; `run` — номер повтора
(`repeat`), `iperf_cpu`/`tunnel_cpus` — привязка нагрузки из конфигурации.

## Отчёт

`bench-report.py` печатает Markdown и/или пишет файлы:

```bash
python3 bench-report.py results.csv                       # в stdout
python3 bench-report.py results.csv --md report.md --agg agg.csv
python3 bench-report.py results.csv --ref kernel-amneziawg
```

Разделы: ячейки (медиана `[min–max]`, отдельно «1 поток» и «много потоков»),
загрузка CPU, сравнение реализаций в процентах (kernel-umbrawg к
kernel-amneziawg, rust к go), агрегат по типу потока, предупреждения (n=1,
фрагментация, потери ≥20%).

### Как читать загрузку CPU

Раздел «Загрузка CPU» показывает по каждой ячейке медиану `hot` (ядра с
busy ≥80%) и суммарную busy% машины, плюс вердикт:

| Вердикт | Условие | Смысл |
|---|---|---|
| `single-core bound` | `hot=1` и суммарно ≥95% | всё упирается в одно ядро: рост `3c`/`-P` без изменения картины — не предел модуля, а полка одного ядра (одна RX-очередь/сокет/TUN-очередь) |
| `параллельно` | `hot≥2` или суммарно ≥130% | работа реально распределена по ядрам |
| `не CPU-bound` | суммарно <50% | CPU не предел: низкая скорость вызвана чем-то другим (потери, лимит, клиент) |
| `промежуточно` | остальное | одно горячее ядро без полки, вывод по цифрам |

Сравнивать надо ячейки с одинаковым `conns`: `conns=1` — всегда один поток и
одна очередь, поэтому `single-core bound` там ожидаем и не является
дефектом реализации. Реальное масштабирование доказывается только на
`conns>=10`: если там `hot≥2`/`busy≥130%`, а скорость растёт — параллелизм
есть; если и там `single-core bound` — предел в одном ядре.

## Детектируемость туннеля (detect.py)

`detect.py` — офлайн-анализатор pcap с UDP-потоком туннеля. Он не измеряет
скорость, а показывает, насколько внешний поток похож на «машинный» профиль,
который цепляет DPI: фиксированные размеры, ACK-часы, метроном, IP-фрагменты.
Крупные GSO-агрегаты (ядро склеивает датаграммы до 63 КБ) считаются отдельно
и не портят метрики размеров. Это **rule-based эвристика, а не ML и не
реальный DPI**: PASS означает лишь «грубых признаков не найдено», FAIL — «есть
признаки, которые надо объяснить». Пороги подобраны консервативно и вынесены
в константы в начале файла.

### Как снять pcap

Снимать надо на underlay-интерфейсе, в обе стороны, с полным снимком пакета:

```bash
sudo tcpdump -i eth0 -s 0 -w tunnel.pcap 'udp and (port 51820 or port 51821)'
sudo tcpdump -i any  -s 0 -w tunnel.pcap 'udp and port 51820'   # SLL-заголовок
```

- `-s 0` обязателен: со срезом (`-s 96`) длины payload искажаются.
- Для лага автокорреляции 120 с нужен дамп хотя бы на 4–5 минут; на коротком
  дампе этот лаг помечается `-`, но остальные метрики считаются.
- Поддержан классический pcap (Ethernet, `DLT_RAW`, Linux SLL/SLL2), little и
  big endian, usec и nsec. pcapng не поддерживается: конвертируйте
  `editcap -F pcap in.pcapng out.pcap`.
- Фильтр `udp` можно не ставить: не-UDP кадры пропускаются и считаются в
  сводке, но фрагментация IP видна только если фрагменты попали в дамп.

### Запуск

```bash
python3 bench/detect.py --pcap tunnel.pcap
python3 bench/detect.py --pcap tunnel.pcap --port-a 51820 --port-b 51821
python3 bench/detect.py --pcap tunnel.pcap --port-a 51820 --port-b 51821 --underlay-mtu 1500
python3 bench/detect.py --pcap tunnel.pcap --port-a 51820 --s4 28 --json
```

`--port-a`/`--port-b` — UDP-порты сторон. Направление `→A` — пакеты, у которых
`dport == port-a` (то есть летят **на** сторону A), `→B` — наоборот; это та же
конвенция, что в `sniff.py`. Если задан только один порт, направление
выводится по `sport`: пакеты с `sport == port-a` считаются `→B`.

`--underlay-mtu N` — MTU underlay-интерфейса. IP-датаграммы длиннее `N`
считаются GSO-агрегатами и исключаются из правил размеров/серий/таймингов
(см. ниже). Без флага порог `8192` B: одиночный Ethernet-кадр такого размера
невозможен, а jumbo-подложку (9000) надо указывать явно, иначе одиночные
9-килобайтные сегменты тоже попадут в «агрегаты». Для 1500-подложки флаг
важен: агрегаты 1.5–8 КБ иначе останутся в выборке.

`--s4 N` — размер S4-префикса профиля обфускации. Эталон ACK-часов тогда
`64+N`; control-кадры несут случайный хвост `0..15` байт, поэтому проверка
ловит весь диапазон `64+N .. 79+N`.

Коды возврата: `0` — все проверки PASS/SKIP, `1` — есть FAIL, `2` — ошибка
(файл, формат, linktype, аргументы). `--json` печатает тот же отчёт
машиночитаемо (`ok`, `verdict`, `metrics`, `checks`, `capture`).

### GSO-агрегаты

Ядро (и Rust-демон) склеивает соседние датаграммы равной длины в UDP GSO,
поэтому на underlay-интерфейсе до сегментации виден один UDP-пакет размером
до 63 КБ, внутри которого лежат `N` одинаковых сегментов. Для DPI это не
одна датаграмма, а пачка; если считать такой пакет одной строкой гистограммы,
`top1_share`, `mod16_entropy`, `max_run`, `run3_share` и `autocorr` дают
ложные FAIL на легитимном FEC/bulk-трафике.

`detect.py` помечает пакет как GSO, если полная длина IP-пакета больше
`--underlay-mtu` (по умолчанию `8192` B), и исключает агрегаты из:

- распределения размеров (`top1_share`, `mod16_entropy`, `small_packets`);
- серий (`max_run`, `run3_share`);
- таймингов (`autocorr`, `interval_cv`);
- FEC-эвристики (`fec_block_uniformity`, `fec_parity_share`).

Доля агрегатов выводится отдельно: `metrics.*.gso_packets`, `gso_share` и
проверка `gso_aggregates` со статусом `SKIP` (не FAIL). Если после исключения
осталось меньше 50 не-GSO пакетов, правила размеров/таймингов переводятся в
`SKIP`: судить о профиле по одним control-кадрам нельзя. Обычные потоки без
агрегатов проверяются ровно как раньше — GSO-поправка не маскирует фиксированные
размеры, метроном и серии (это закреплено тестами).

### Метрики и пороги

Размер пакета — это длина **UDP payload** (внешняя туннельная датаграмма), а не
кадр Ethernet: именно её видит DPI. Все метрики считаются по всему потоку и
отдельно по направлениям, если порты заданы. Пакеты, распознанные как
GSO-агрегаты, в метрики размеров/серий/таймингов не входят (см. выше).

| Проверка | Порог | Что означает |
|---|---|---|
| `capture_size` | `>= 50` пакетов | меньше — метрики недостоверны, проверка FAIL |
| `gso_aggregates` | `ip_len <= --underlay-mtu` (8192) | доля GSO-агрегатов; при их наличии `SKIP` — они исключены из остальных правил |
| `top1_share` | `<= 0.15` | доля самого частого размера; при `>=50%` пакетов размером `>= 1200 B` порог смягчается до `0.50`, потому что full-MTU поток физически не может быть разнообразным |
| `ack_clock_share` | `<= 0.15` | доля пакетов `64+s4 .. 79+s4` B — ACK-часы и пустые подтверждения; control-кадры несут случайный хвост `0..15`, поэтому окно асимметричное |
| `mod16_entropy` | `>= 3.5` бит | энтропия распределения `len % 16`; низкая означает квантование размеров (паддинг до 16) — сам по себе fingerprint. На full-MTU нагрузке проверка SKIP |
| `ip_fragments` | `== 0` | доля IP-фрагментов; фрагмент — аномалия и ломает обфускацию |
| `max_run` | `<= 8` | максимальная серия одинаковых размеров подряд |
| `run3_share` | `<= 0.30` | доля пакетов в сериях одинакового размера `>= 3` |
| `fec_block_uniformity` | `<= 0.50` | доля найденных FEC-блоков с разбросом длин `<= 1 B`; у настоящих шардов есть случайный хвост `0..15`. На full-MTU нагрузке и при `< 2` блоков SKIP |
| `fec_parity_share` | `<= 0.50` | оценка доли parity-шардов среди FEC-блоков; parity не должен доминировать над data-шардами. SKIP без блоков |
| `interval_cv` | `>= 0.3` | CV межпакетных интервалов; низкий — метроном/жёсткий пейсинг |
| `autocorr` | `abs(r) <= 0.5` | автокорреляция ряда «пакетов в 100-мс бине» на лагах 1/2/5/10/120 с; ищет периодические CAPS/keepalive |
| `small_packets` | `<= 0.30` | доля пакетов `< 100` B |
| `ack_pps_ratio` | `<= 4.0`, для FEC `<= 20.0` | перекос pps ACK-пакетов между направлениями. При явно односторонней нагрузке (в слабом направлении <5% байт данных) проверка SKIP: обратный канал несёт только ACK, и асимметрия ожидаема. Если найден FEC (`>= 2` блоков), порог мягче (20). Для симметричного потока без FEC порог остаётся 4 |

Отчёт также печатает `pps`, средний размер, окно захвата, число фрагментов и
пакетов без известного направления — по ним удобно проверять, что дамп снят
корректно. В JSON у каждой группы есть `packets_total` (все UDP-пакеты),
`packets` (только не-GSO, по ним считаются метрики) и `gso_packets`/`gso_share`.
Полная гистограмма размеров лежит в JSON (`metrics.all.histogram`).
Хвостовые IP-фрагменты (offset != 0) не содержат UDP-заголовка: они попадают в
счётчик фрагментации, но не в гистограмму размеров. Файл читается целиком в
память, поэтому для дампов в единицы гигабайт снимайте окно короче.

### Тесты

```bash
python3 bench/tests/test-detect.py
```

Тесты генерируют синтетические pcap: «плохой» профиль (кратные 16 размеры,
20% ACK по 64 B, ровный шаг 10 мс) должен дать FAIL, «хороший» (вариативные
размеры, случайные интервалы) — PASS; отдельно проверяются фрагментация,
big-endian/nsec, `DLT_RAW`, Linux SLL, VLAN, `--s4`, padded ACK (control-хвост
`0..15`), FEC-блоки (серии `k+m`, parity, ровные длины, adaptive-ступенька),
GSO-агрегаты (не дают FAIL, не маскируют реальную обфускацию, `--underlay-mtu`,
поток целиком из GSO), `ack_pps_ratio` (SKIP для односторонней нагрузки,
порог 20 для FEC, FAIL для симметричного потока без FEC) и pcapng-ошибка.

Команда `python3 -m unittest discover -s bench/tests -p "test-detect.py"` на
современном Python тесты не находит: `unittest discover` импортирует только
файлы с валидным именем модуля (`VALID_MODULE_NAME` в `unittest/loader.py`), а
дефис в `test-detect.py` таким не является. Поэтому запускать надо напрямую
(`python3 bench/tests/test-detect.py`); по той же причине общий прогон
`python3 -m unittest discover -s tests -p 'test_*.py'` этот файл не
подхватывает. Переименование в `test_detect.py` сделало бы его видимым для
discover, но ломает оговорённое имя файла.

## Ограничения стенда

- **veth не даёт очередей сам по себе.** `ip link add ... numtxqueues N
  numrxqueues N` задаёт только максимум: сразу после создания реально
  активна 1 очередь (`ethtool -l` → RX:1/TX:1, в sysfs только `rx-0`/`tx-0`).
  Рабочий способ — `ethtool -L <dev> rx N tx N` в каждом netns **для каждого
  конца пары**. Скрипт это делает и пишет фактическое число очередей в diag
  (`QUEUES:`), но при ядре без такой поддержки останется 1 очередь.
- **RSS на veth отсутствует.** `ethtool -x` → `Operation not supported`,
  аппаратной раскладки нет. Есть только software RPS (`rps_cpus`) и XPS
  (`xps_cpus`); по умолчанию они не меняются (RPS=0, XPS=0 = все CPU).
  RPS помогает только многопоточным сценариям: один поток — одна очередь.
- **Один UDP/TCP-поток не масштабируется на 3c** независимо от реализации:
  это ограничение veth/одной очереди, а не модуля. Для вывода о ядрах нужны
  ячейки `conns>=10`.
- **iperf3-клиент закреплён на одном ядре** (`IPERF_CPU`). На 100 потоках он
  сам может стать бутылочным горлышком; теперь это видно напрямую: если
  `IPERF_CPU` перегружен в `per_cpu`, а туннельные ядра простаивают, узкое
  место — клиент, а не реализация.
- **Go-эталон с заглушкой обфускации данных** (`obf_data.go`, `Obfuscate=copy`),
  поэтому `obf=1` у go не сравним с настоящей обфускацией UmbraWG.
- **netem loss ставится только на `bveth0`** (ns0 → ns1), то есть потери
  односторонние.
- **workqueue cpumask** для kernel-реализаций выставляется по числу ядер
  режима (`1c` → 0, `3c` → 0-2); конкурирующие задачи на этих ядрах влияют
  на результат, поэтому проверка занятости обязательна.
- **Параллельные замеры недопустимы.** Даже короткий SMOKE при чужой сборке
  или функциональных тестах даёт недостоверные цифры.
- **MTU-guard — эвристика**: `OVERHEAD_BASE=80` плюс `S4` из профиля.
  Реальная фрагментация дополнительно ловится счётчиками ядра, но уже по факту.

## CI (bench-ci.yml)

`.github/workflows/bench-ci.yml` запускается на push/PR при изменениях
`bench/**`, `umbrawg-rs/**`, `umbrawg-linux-kernel-module/**` или самого
workflow, вручную (`workflow_dispatch`) и по ночному cron (03:00 UTC).
Джоб `bench` на `ubuntu-latest`:

1. проверяет `bash -n bench/wire-ext.sh bench/ext-tests.sh bench/ext-matrix.sh`
   и ставит на раннер `bc`, `build-essential`, `clang`, `libelf-dev`, `lld`,
   `llvm`, `kmod`, `iperf3`, `iproute2`, `python3`, `tcpdump`;
2. собирает модуль в контейнере `archlinux:base-devel` (`linux-headers`,
   `KERNELDIR=/usr/lib/modules/*/build`, `LLVM=1` при clang-ядре): заголовки
   Ubuntu-раннера не содержат `crypto/aes-gcm.h`;
3. собирает `umbrawg-rs` (`cargo build --release --locked -p umbrawg`) и `uwg`
   (`cargo build --release --locked -p uwg`);
4. на каждом push/PR гоняет `python3 bench/tests/test-detect.py`,
   `python3 bench/tests/test-golden-pcap.py` и
   `PLAN_ONLY=1 CASES="mixed-fec21 kernel-fec21 rust2-fec21 profile-mismatch adaptive-clean clean-fec21" bash bench/ext-tests.sh`;
5. только на push в master, `workflow_dispatch` и cron выполняет реальный
   interop: `sudo DUR=2 CASES="rust2-fec21" bash bench/ext-tests.sh`.

Полный прогон требует root (netns, `insmod`, `tc`, `tcpdump`) и занимает
раннер на несколько минут, поэтому в PR он не запускается: сборка ловит
ошибки компиляции, `PLAN_ONLY` — рассинхрон `CASES`/`known_case`/`print_plan`,
detect-тесты — регрессии анализатора. Логи прогонов (если были) уходят в
артефакт `bench-interop-logs`.

Ограничения: сборка модуля идёт в Arch-контейнере и зависит от доступности
`linux-headers` в pacman; модуль для другого ядра всё равно не загрузится
из-за vermagic, поэтому шаг падает явно, а не пропускается молча. Реальный
interop на раннере покрывает только `rust2-*` (Rust↔Rust без модуля); кейсы
`mixed`/`kernel`/`profile-mismatch`/`clean` гоняются на стенде, а в CI для них
проверяется только `PLAN_ONLY`.

## CI (bench-matrix.yml)

`.github/workflows/bench-matrix.yml` запускается по ночному cron (04:00 UTC) и
вручную (`workflow_dispatch`), **не** на каждый push/PR. Джоб `bench-matrix`
на `ubuntu-latest`:

1. проверяет `bash -n bench/wire-ext.sh bench/ext-matrix.sh`;
2. ставит Rust и кэширует сборку, собирает `umbrawg` (`cargo build --release
   --locked -p umbrawg`, manifest `umbrawg-rs/Cargo.toml`) и `uwg`
   (`umbrawg-tools`);
3. ставит `iperf3`, `iproute2`, `tcpdump`, `python3`;
4. гоняет `PLAN_ONLY=1` для матрицы `IMPL_LIST=rust2`, `FEC_LIST="off 2:1 8:2
   adaptive"`, `LOSS_LIST="0 2"`;
5. выполняет полный прогон
   `sudo -E env DUR=2 IMPL_LIST=rust2 FEC_LIST="off 2:1 8:2 adaptive"
   LOSS_LIST="0 2" bash bench/ext-matrix.sh`.

Модуль `umbrawg.ko` **не собирается и не загружается**: на раннере нет
подходящего ядра, а режим `rust2` (Rust↔Rust без модуля) его не требует.
Поэтому workflow покрывает только `rust2`; interop с kernel-модулем остаётся
на стенде и в `bench-ci.yml`. Логи и CSV (`bench/tmp/ext-matrix-*.csv` и
`bench/tmp/ext-matrix-*/`) уходят в артефакт `bench-matrix-logs`
(`if: always()`, retention 30 дней).

## Проверки

```bash
bash -n bench.sh bench-lib.sh tests/test-bench-lib.sh
bash -n bench/wire-ext.sh bench/ext-matrix.sh bench/ext-tests.sh
bash -n bench/mem-matrix.sh
PLAN_ONLY=1 bash bench/ext-tests.sh
PLAN_ONLY=1 bash bench/mem-matrix.sh
bash tests/test-bench-lib.sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 bench/tests/test-detect.py
python3 bench/tests/test-golden-pcap.py
python3 bench/tests/test_bench_report.py
python3 -c 'import yaml; yaml.safe_load(open(".github/workflows/bench-ci.yml"))'
python3 -c 'import yaml; yaml.safe_load(open(".github/workflows/bench-matrix.yml"))'
```
