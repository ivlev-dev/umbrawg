# Стенд замера пропускной способности UmbraWG

Изолированный стенд: два netns (`bn0`, `bn1`), veth-пара `bveth0`/`bveth1`,
в каждом ns — интерфейс `uwgb0`/`uwgb1` (kernel-модуль `umbrawg`, `amneziawg`
или userspace `umbrawg`/`amneziawg-go`). Нагрузка — `iperf3`, приёмник
закреплён на отдельном ядре (`IPERF_CPU`, по умолчанию 3).

Скрипты не привязаны к конкретному каталогу: `BENCH_DIR` — каталог самого
`bench.sh`, `REPO_ROOT` — репозиторий `umbrawg-tools`, `WORKSPACE_ROOT` —
каталог, где лежат соседние репозитории (`umbrawg-tools`,
`umbrawg-linux-kernel-module`, `umbrawg-rs`, `netlink-packet-umbrawg`).
Всё остальное переопределяется переменными окружения.

## Быстрый старт

Из корня репозитория `umbrawg-tools` (нужен root: netns, insmod, iperf3):

```bash
SMOKE=1 DURATION=1 IMPL_LIST="kernel-umbrawg" bash bench/bench.sh
PLAN_ONLY=1 SMOKE=1 FORCE=1 bash bench/bench.sh            # план без трафика
IMPL_LIST="kernel-umbrawg kernel-amneziawg" MODE_LIST="1c 3c" REPEATS=5 bash bench/bench.sh
PROTO_LIST=udp UDP_RATE_LIST="1G 0" CONNS_LIST="1 10" bash bench/bench.sh
python3 bench/bench-report.py results-20261116-120000.csv --md report.md --agg agg.csv
```

`PLAN_ONLY=1` не требует root, бинарников и модуля: печатает план, создаёт
пустой CSV с заголовком и отчёт.

## Пути

Значения по умолчанию выводятся из расположения `bench.sh`: корневой
`bench/` видит компоненты монорепозитория рядом, а `umbrawg-tools/bench/`
поднимается на уровень выше. Если деревья лежат в другой раскладке
(worktree, отдельная копия), достаточно задать переменные окружения.

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `BENCH_DIR` | каталог `bench.sh` | где лежат `bench-lib.sh`, `obf-params.conf`, отчёт |
| `REPO_ROOT` | `$BENCH_DIR/..` | корень `umbrawg-tools` (оттуда `target/release/uwg`) |
| `WORKSPACE_ROOT` | `$REPO_ROOT/..` | каталог соседних репозиториев |
| `RUSTDIR` | `$WORKSPACE_ROOT/umbrawg-rs`, затем `$WORKSPACE_ROOT/rust` | репозиторий `umbrawg-rs` |
| `MODDIR` / `MODULE_DIR` | `$WORKSPACE_ROOT/umbrawg-linux-kernel-module/src`, затем `$WORKSPACE_ROOT/module/src` | каталог с `umbrawg.ko` |
| `UWG` | `$REPO_ROOT/target/release/uwg` | CLI `uwg` |
| `DAEMON` | `$RUSTDIR/target/release/umbrawg`, затем `$RUSTDIR/umbrawg` | userspace-демон |
| `GO_BASELINE` | `/opt/baseline/amneziawg-go`, `/usr/local/bin/amneziawg-go`, `/usr/bin/amneziawg-go` | эталон `amneziawg-go` |
| `OBF` | `$BENCH_DIR/obf-params.conf` | профиль обфускации |
| `RESULT` | `$BENCH_DIR/results.csv` | CSV результатов; diag — `$RESULT.diag`, отчёт — `$RESULT.md` |
| `REPORT_PY` | `$BENCH_DIR/bench-report.py` | генератор отчёта |
| `LOCK` | `/tmp/uwg-bench.lock` | flock стенда |

Пример для развёрнутого стенда:

```bash
RUSTDIR=/path/to/umbrawg-rs \
MODDIR=/path/to/umbrawg-linux-kernel-module/src \
UWG=/path/to/umbrawg-tools/target/release/uwg \
DAEMON=/path/to/umbrawg-rs/target/release/umbrawg \
bash bench.sh
```

Перед прогоном (не в `PLAN_ONLY=1`) проверяется наличие `$UWG`, `$MODDIR/umbrawg.ko`,
`$DAEMON`, `$GO_BASELINE` для выбранных `IMPL_LIST`, а также `ip`, `iperf3`,
`python3`, `ping`; при нехватке печатается `REQUIRE_FAILED` с кодом выхода 5.

## Ключи и секреты

В репозитории нет рабочих ключей: `obf-params.conf` — шаблон с
`PrivateKey = <PRIVATE_KEY>` и `HeaderProtectionKey = <HEADER_PROTECTION_KEY>`.
`obf_block_from_conf` (`bench-lib.sh`) подставляет сгенерированные значения
во время прогона (`uwg genkey`, `uwg pubkey`).

`HeaderProtectionKey` должен совпадать на обеих сторонах туннеля.
**Публично известный HP-ключ убивает обфускацию заголовков**: неизменный
префикс пакетов позволяет опознать трафик, поэтому ключ нельзя коммитить,
публиковать в отчётах или переиспользовать между стендами. Локальные
сгенерированные конфиги в git не попадают.

## Переменные

Существующий интерфейс сохранён: `IMPL_LIST`, `MODE_LIST`, `PROTO_LIST`,
`CONNS_LIST`, `LOSS_LIST`, `OBF_LIST`, `PEERS_LIST`, `DURATION`, `SMOKE`,
`RESULT`, `PLAN_ONLY`, `FORCE`, `UDP_RATE`, `UNDERLAY_MTU`, `TUN_MTU`,
`RUN_ID`, `CPU_HOT_PCT`. Ниже — остальное.

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `REPEATS` | 3 (SMOKE: 1) | число повторов каждой ячейки |
| `UDP_RATE` | 1G | суммарная предложенная скорость UDP на всю ячейку |
| `UDP_RATE_LIST` | пусто | список скоростей UDP, переопределяет `UDP_RATE`; `0` = без лимита |
| `TUN_MTU` | 1420 | MTU туннельных интерфейсов |
| `UNDERLAY_MTU` | 9000 | MTU veth (underlay); передаётся демонам rust/rust-par как `UMBRAWG_UNDERLAY_MTU` |
| `UMBRAWG_UNDERLAY_MTU` | =`UNDERLAY_MTU` | env демона (rust/rust-par): MTU underlay для GSO/фрагментации; задаётся автоматически из `UNDERLAY_MTU` |
| `GSO_SEGMENTS` | пусто | если задан, передаётся демонам rust/rust-par как `UMBRAWG_GSO_SEGMENTS` |
| `RUST_RX_SCHED` | peer | планировщик RX для `rust-par` (`peer` или `queue`); env `UMBRAWG_RX_SCHED` |
| `RUST_PARALLEL` | 0 | 1 — добавить `rust-par` в список реализаций по умолчанию |
| `OVERHEAD_BASE` | 80 | базовый оверхед туннеля (IPv4+UDP+WG) для MTU-guard |
| `ALLOW_FRAGMENT` | 0 | 1 — разрешить заведомо фрагментированный путь |
| `VETH_QUEUES` | `nproc` | число очередей veth (max для `numtxqueues`/`numrxqueues`) |
| `VETH_RX_Q` / `VETH_TX_Q` | `VETH_QUEUES` | сколько очередей реально включить через `ethtool -L` |
| `RPS_MASK` | off | hex-маска для `rps_cpus` на rx-очередях veth (`off` — не трогать) |
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
   **Предупреждение:** при underlay 1500 для `obf=1` (S4=28) нужен
   `TUN_MTU ≤ 1392` (obf=0) / `≤ 1380` (obf=1); иначе путь фрагментируется.
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

`impl,mode,proto,conns,loss,obf,peers,mbit,extra,run,repeat,lost_percent,udp_rate,udp_mode,streams,frag,cpu_hot,cpu_total`

Первые 9 колонок совместимы со старым форматом (`extra`: retransmits для TCP,
lost_percent для UDP). `mbit` — `sum_received`, то есть goodput.
`FAIL` в `mbit` — прогон не удался. `cpu_hot`/`cpu_total` — необязательные:
число ядер с busy ≥ `CPU_HOT_PCT` и суммарная busy% машины за ряд; при
недоступности `/proc/stat` там `-`. Старые парсеры, читающие первые 16
колонок, не ломаются. Старый `results.csv` (другая схема) не
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

## Графики и отчёт

`bench-plot.py` строит самодостаточный HTML-файл с инлайн-SVG столбчатыми
графиками (без внешних зависимостей, только стандартная библиотека Python):

```bash
python3 bench/bench-plot.py results.csv -o report.html --title "UmbraWG bench"
python3 bench/bench-plot.py results.csv -o report.html   # заголовок по умолчанию
```

Отчёт группирует данные по `proto`, `obf`, `conns`, `mode`, сравнивает
реализации по медиане `mbit` (медиана по `repeat`), показывает таблицу
`реализация × ячейка` (медиана, min–max, потери `extra`, CPU-вердикт) и
предупреждения о ячейках с потерями UDP > 1%. При отсутствии данных скрипт
завершается с кодом 1. Тесты: `python3 -m unittest discover -s bench/tests`.

## Сравнение прогонов

`bench-compare.py` сравнивает два CSV-прогона стенда: агрегирует медиану
`mbit` и медиану потерь (`extra`: для UDP — `lost_percent`, для TCP —
ретрансмиты) по ячейке `(impl, mode, proto, conns, loss, obf, peers)`,
сопоставляет ячейки baseline/candidate, считает Δ% и помечает регрессии
(падение пропускной способности больше порога или рост потерь/ретрансмитов
больше 1 п.п.):

```bash
python3 bench/bench-compare.py baseline.csv candidate.csv
python3 bench/bench-compare.py baseline.csv candidate.csv --threshold 10 --md diff.md --json diff.json
```

Статусы: `OK`, `REGRESSION`, `BETTER`, а также `MISSING`/`NEW` для
отсутствующих ячеек. Код выхода: 0 — регрессий нет, 1 — есть регрессии,
2 — ошибка входных данных. После оптимизации прогоняйте новый результат
против базового: `python3 bench/bench-compare.py ab-master.csv ab-wire.csv`.

## A/B коалесинга пробуждений

`wakeup-ab.sh` сравнивает две сборки модуля на одном стенде. Каждый раунд
прогоняет `bench.sh` для обеих сборок, порядок вариантов чередуется —
дрейф машины и нагрев не смещают разницу в одну сторону. Разбор результатов
делает `wakeup-analysis.py`: медианы по ячейкам, парные Δ% по совпадающим
повторам, знак пар, ретрансмиты/потери и `cpu_total`.

Что меряется в каждой сборке: `DURATION=8`, `REPEATS=1`, TCP `conns=1/10`,
UDP 1G, `obf=0/1`, `mode=1c/3c` — 16 ячеек, примерно 6–8 минут на вариант
за раунд. Скрипт ждёт load average ниже `IDLE_LOAD_MAX`, поэтому рядом не
должно быть сборок и функциональных тестов.

```bash
# нужен root; обе сборки уже собраны (в src лежит umbrawg.ko)
MASTER=$WORKSPACE_ROOT/module-master/src \
WAKEUP=$WORKSPACE_ROOT/module-wakeup/src \
bash bench/wakeup-ab.sh --rounds 5
python3 bench/wakeup-analysis.py bench/results/wakeup-ab
```

Варианты каталогов можно задать флагами `--master`/`--wakeup` или
переменными `MASTER`/`WAKEUP`; если рядом с репозиторием есть
`module-master/src` и `module-wakeup/src`, они находятся сами.

| Переменная / флаг | По умолчанию | Смысл |
|---|---|---|
| `MASTER`, `--master` | `$WORKSPACE_ROOT/module-master/src`, затем `$WORKSPACE_ROOT/umbrawg-linux-kernel-module/src` | сборка-база |
| `WAKEUP`, `--wakeup` | `$WORKSPACE_ROOT/module-wakeup/src`, затем `$WORKSPACE_ROOT/umbrawg-linux-kernel-module/src` | сборка с изменением |
| `ROUNDS`, `--rounds` | 5 | число раундов (каждый раунд — оба варианта) |
| `OUTDIR`, `--outdir` | `$BENCH_DIR/results` | каталог CSV |
| `TAG`, `--tag` | `wakeup-ab` | префикс файлов |
| `COOLDOWN`, `--cooldown` | 20 | пауза между раундами, секунд |
| `IDLE_LOAD_MAX` | 0.9 | порог load average перед прогоном |
| `DURATION`, `CONNS_LIST`, `OBF_LIST`, `MODE_LIST`, `PROTO_LIST`, `PEERS_LIST`, `LOSS_LIST`, `UDP_RATE_LIST`, `IMPL_LIST` | как у `bench.sh` (см. дефолты скрипта) | матрица ячеек |

Полный прогон (5 раундов × 2 варианта) занимает около 1,5–2 часов. Каждый
вариант оставляет `$OUTDIR/$TAG-master.csv` и `$OUTDIR/$TAG-wakeup.csv`
плюс `.diag`, `.agg.csv`, `.md` от `bench.sh`; исходные CSV всех повторов
сохраняются (в них пишется `RUN_ID=<вариант>-r<раунд>`), поэтому анализ
можно перезапускать без повторных замеров. `wakeup-analysis.py` без
аргументов берёт `bench/results/wakeup-ab`; короткое имя тоже ищется в
`bench/results`.

## Масштабирование по пирам

`peer-scaling.py` меряет, как растёт суммарный goodput с числом пиров:
1/2/4 пары «своё клиентское устройство ↔ свой серверный пир». Потоки iperf3
(`--conns`, по умолчанию 10) делятся между пирами поровну. Режим
`--single-server` кладёт все 4 пира на одно серверное устройство и один
сокет — так видно, упирается ли масштабирование во внешний сокет или в
per-peer NAPI.

Требования: root (netns, insmod, workqueue cpumask), **4 пары
устройств/пиров** (интерфейсы `uwgp0..3` и `uwgq0..3`), `iperf3`, собранный
`umbrawg.ko` или userspace-демон. Стенд сам создаёт `bn0`/`bn1`, veth с
`nproc` очередями, конфиги с обфускацией из `obf-params.conf` и снимает
CPU-профиль по каждому прогону.

```bash
python3 bench/peer-scaling.py --print-defaults          # пути без запуска
python3 bench/peer-scaling.py --variant master --rounds 3
python3 bench/peer-scaling.py --variant master-single --single-server --rounds 3
python3 bench/peer-scaling.py --variant rust --impl rust-par --mode 3c
```

Пути по умолчанию выводятся из расположения скрипта и `WORKSPACE_ROOT`
(`UWG`, `DAEMON`, `KO`, `OBF`, `OUT`); их можно переопределить переменными
`WORKSPACE_ROOT`, `UWG`, `DAEMON`, `GO_BASELINE`, `OBF`, `AWG` или флагами
`--ko`, `--daemon`, `--go-bin`, `--obf-conf`, `--out`. Матрица:
`--peers-list "1 2 4"`, `--obf-list "0 1"`, `--protos "tcp udp"`, `--conns 10`,
`--duration 8`, `--rounds 3`, `--rate 1G` (UDP с лимитом; `0` — без лимита).
`--client-cpus`/`--server-cpus` задают привязку iperf3.

Один набор (2 значения obf × 3 набора пиров × 2 протокола × 3 повтора по
8 с) — около 5 минут трафика, с созданием топологии и ожиданием туннеля
10–15 минут; прогон с `--single-server` стоит столько же. Результат
дописывается в `bench/results/peer-scaling.csv` (по строке на повтор):
`variant,mode,obf,peers,conns,proto,rep,mbit,retrans,lost_percent,
cpu_total,hot_cpus,top_threads,per_cpu`. `cpu_total` и `per_cpu` — busy% всей
машины и по ядрам за прогон, `top_threads` — вклад потоков (включая
`napi/uwgq*`), `hot_cpus` — число ядер с busy ≥ 80%. Итоговые таблицы и
разбор — в [PEER-SCALING.md](PEER-SCALING.md).

## Профилирование wakeup

Два скрипта для разбора, куда уходит время на пробуждениях:

- `wakeup-count.sh <master|wakeup> [повтор]` — `perf record` по
  `sched:sched_wakeup` за один прогон `bench.sh`, печатает top-10 задач,
  которые будят воркеров.
- `wakeup-profile.sh <master|wakeup> <метка>` — `perf record -F 1500 -g` по
  всему прогону, печатает строку `Mbit` и top-30 символов с долей сэмплов
  (`queue_work_on`, `__queue_work`, `try_to_wake_up`, `ttwu_do_activate`).

Оба требуют root, `perf` с символами ядра (`kernel.perf_event_paranoid`
не выше 1, иначе `perf record -a` не даст данные) и свободный стенд: перед
запуском скрипт выгружает `umbrawg`, ждёт load ниже `IDLE_LOAD_MAX`, ждёт
исчезновения `bn0`/`bn1` и чужих `iperf3`.

```bash
bash bench/wakeup-count.sh master 1
bash bench/wakeup-profile.sh wakeup p1
```

`MODDIR` по умолчанию — `$WORKSPACE_ROOT/module-<вариант>/src`, затем
`$WORKSPACE_ROOT/umbrawg-linux-kernel-module/src`; матрица задаётся
`DUR`/`PROTO`/`CONNS`/`MODE`/`OBF` (по умолчанию 6–8 с, TCP, 1 поток, `1c`,
`obf=0`), частота профиля — `PERF_HZ`. Один запуск занимает 1–2 минуты
(сам прогон 6–8 с плюс ожидание чистого стенда).

Выходные файлы: `/tmp/wk-<вариант>-<повтор>.{data,log,csv}` и
`/tmp/prof-<вариант>-<метка>.{data,log,csv}`, префикс меняется через `OUT`.
В stdout — счётчики по задачам (count) или доля символов и строка `Mbit`
(profile). `perf.data` можно разбирать дальше: `perf report -i ... --stdio`,
`perf script -i ...`.

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

## Проверки

Из корня репозитория (без root, кроме `bash -n` ничего не нужно):

```bash
bash -n bench/*.sh bench/tests/test-bench-lib.sh
bash bench/tests/test-bench-lib.sh                          # 62 проверки
python3 -m py_compile bench/*.py bench/tests/*.py
python3 -m unittest discover -s bench/tests -p 'test_*.py'  # 60 тестов
PLAN_ONLY=1 FORCE=1 IMPL_LIST="" bash bench/bench.sh        # план без root
bash bench/wakeup-ab.sh --help                              # справка без запуска
bash bench/wakeup-count.sh --help
bash bench/wakeup-profile.sh --help
python3 bench/wakeup-analysis.py --help
python3 bench/peer-scaling.py --print-defaults               # только пути
```

Тесты хелперов проверяют `cpu_mask`, MTU-guard, разбор скоростей UDP,
счётчики фрагментации, CPU-срезы, guard занятости, разрешение путей
(`first_existing_dir`/`first_existing_file`) и запуск `bench.sh` в режиме
`PLAN_ONLY` без root. `test_wakeup_analysis.py` проверяет разбор A/B CSV:
пропуск `FAIL`, номер повтора из `run`, медианы, парные Δ только по общим
повторам и формат строк отчёта.

## Совместимость

Отчёт `bench-report.py` читает и новый CSV (18 колонок), и старый формат
(9 колонок): при несовпадении заголовка `bench.sh` не перезаписывает файл,
а пишет `results-<RUN_ID>.csv`. Юнит-тесты отчёта лежат в
`bench/tests/test_bench_report.py`.

## Эталонные матрицы

Эталонные прогоны для сравнений лежат в `bench/baselines/` (см. `bench/baselines/README.md`). Сравнение: `python3 bench/bench-compare.py bench/baselines/final4-20261117.csv <new.csv> --threshold 10 --md report.md`.
