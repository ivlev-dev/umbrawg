# Changelog

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версии соответствуют [SemVer](https://semver.org/lang/ru/).

## [0.4.1] — 2026-11-23

### FEC

- FEC RTT: partial flush переведён с jiffies-таймера на soft hrtimer с
  окном **150–450 мкс**, таймер снимается в хвосте emit. RTT `2:1` снизился
  с 5.05–5.56 до **1.099 мс**, mixed kernel↔Rust — 0.727 мс; без FEC —
  0.387. `bpftrace`: `timeout/emit` 3.1% → 1.9% (390 → 135/с), потери
  `8:2` на 10 Мбит/с — 11.1% → 8.9%.
- RX-таймаут блока остаётся 5 мс (`timer_list`, квантуется HZ); полный блок
  отдаётся сразу по `k` шардам, таймаут — только граница ожидания
  потерянного шарда.
- GSO-группа FEC-шардов ограничена числом parity `m`: при `2:1` шарды не
  агрегируются, при `8:2` — не более двух в группе. Супер-датаграмма
  теряется целиком, поэтому группа больше `m` сделала бы блок
  невосстановимым.
- `FEC_PARTIAL` (CAPS бит 4): partial-блок при поддержке пира кодируется
  `k' = n`, `m' = m` (data + parity), без флага остаётся legacy `m' = 0`.
  RX принимает `k' <= k`, `m' <= m`, `k' + m' <= k + m`; полные блоки не
  меняются. Sparse ping 10 pps + 2% потерь: 3–6% → 0–0.5%.
  Модульный параметр `fec_partial=0` выключает флаг для проверки
  совместимости.
- Adaptive: окно оценки ждёт 1 секунду оседания, поэтому reorder не
  армит parity; оценщик сбрасывается по keypair (counter начинается с нуля
  на rekey).
- Бюджет MTU считается от `underlay-mtu` с учётом `S4`:
  `underlay − 132 − S4`, MTU понижается при FEC (1500 → 1368, при `S4=28`
  → 1340) и восстанавливается при выключении. Ручной MTU принимается как
  новая база; floor — `min(576, base)`, поэтому база 500 не поднимается
  до 576.
- RX: short bitmap `1..8` маскируется как «не сообщено», а не как дыры;
  таймауты ACK/FEC квантуются HZ.

### CAPS

- Нулевой CAPS отзывает устаревший FEC-профиль, только если пир показывал
  extension-трафик; не чаще раза в 2 с и через общий `next_send`-гейт,
  поэтому revoke больше не уходит потоком кадров (раньше — до 199k кадров).
- Гейт `next_send` пейсит все отправки CAPS: серия ретраев 250 мс, затем
  backoff до 2 с.
- Неподтверждённая реклама (пир всё ещё показывает другой FEC-профиль)
  ретраится до 3 раз на эпоху; после совпадения профиля ретрай снимается,
  так что потеря пары CAPS не оставляет обе стороны в legacy до rekey.
- Ответ на изменившийся профиль — одна попытка на стимул; ядро откладывает
  его до `last_sent + 200 мс` и отправляет по delayed-ACK-таймеру, а не
  теряет. На идентичный повтор — не больше двух ответов на эпоху.

### BBR

- BBR-пейсинг, учёт `inflight` и `cwnd`-гейт включаются только при `ACK`
  в CAPS пира; без ACK трафик не шейпится, `inflight`/pacing не растут.
  При потере ACK накопленный `inflight` сбрасывается.
- `cwnd` работает как ACK-clocked гейт после loss-cut
  (`full_bw_reached && inflight_hi < cwnd`); floor `pacing_rate × 5 мс`
  (потолок 4 MiB) и аварийный выход через 5 мс без ACK.
- Watermark и `on_drop` учитываются как потеря/возврат байтов; ring
  привязан к keypair, ACK чужого keypair игнорируется.
- Loss-порог — 20% раунда; потери ниже порога не режут окно.
- `bbr_stats` получил `peers_no_ack` (вложенный атрибут 9): пиры без ACK
  в CAPS; BBR к ним не применяется, в агрегаты они не входят.

### Производительность

- Work stealing для крипто-очередей (`c5457f06` + `0844f750`): при backlog
  цепочек пира `depth > 4` producer публикует запрос, свободный воркер
  другого CPU забирает его и дренит ring жертвы. Порог — compile-time
  константа, **без `module_param`**; порядок пакетов и state machine не
  меняются. Single-flow — **3.08–3.14 Гбит/с** (round-robin 2.40,
  local-only 2.31–2.35); 5 пиров — 7.44 → **7.80**; 10 — **8.06–8.45**;
  50 — **8.25–9.12**, fairness **1.4–2.2** (round-robin 4.84–5.19/7.9–10.9,
  local-only 7.82/1.92), `awg-kernel` — 6.69–6.98/1.70. Переключений
  контекста на 50 пирах — ~57 тыс/с против 310 тыс/с; UDP 50×8 Мбит/с —
  0.400 Гбит/с/0%.
- Per-CPU крипто-очереди (`ae0906c7`): пакет ставится в `ptr_ring`
  **текущего** CPU (`get_cpu`/`put_cpu`) вместо round-robin по online-CPU.
  Локальность сохраняет батч и горячие cacheline'ы; промежуточный результат
  на 50 пирах — 7.82 Гбит/с (7.14–8.01), fairness 1.92. Промежуточная
  плата — single-flow 2.31–2.35; снята work stealing.
- Единый бюджет in-flight `crypt_queue_budget` (module_param, по умолчанию
  **4096**, clamp 64…8192): ring на CPU — `max(128, budget /
  possible_cpus())`, слот хранит цепочку skb. Убирает умножение буфера на
  число CPU (~68 МБ и RTT 130 мс при 50 пирах). Бюджет 8192 не даёт
  агрегата и ухудшает fairness.
- Счётчики `tx_dropped`/`rx_dropped` на `-EPIPE` при переполнении ring;
  при 50 пирах `rx_dropped` 0.35–0.64%, `tx_dropped` 0.
- AES-256-GCM на HEAD `0844f750`: 1 пир — 3.483 против 3.139 у ChaCha
  (+10.8%), 5 пиров — 9.029 против 7.798 (+15.8%), mixed 8.092; 50 —
  10.652 против 8.246 (+29%), mixed 7.797. UDP 50×8 — 0.400/0% у всех.
  На AES-NI/VAES AES — предпочтительный шифр; mixed зависит от доли
  AES-пиров, ChaCha — fallback без AES-NI/VAES.
- Классификация transport-first (`67f8e66d`, `receive.c`): data-пакет
  проверяется первым. При random trailers гейты control-типов ослаблены до
  `>=`, и transport-пакет по чужому offset попадал в их диапазон — **72
  пакета** на 4.49M RX молча терялись под нагрузкой, каждый дроп ронял
  `cwnd`; после фикса **0/4.44M**. Медиана RTT на 5 пирах — 0.48–0.53 →
  **0.10–0.22 мс**, throughput в пределах шума.
- CAPS-гейт на RX-пути (`uwg_peer_caps_may_send()` перед
  `uwg_ext_maybe_send_caps()`): при выключенных BBR/FEC и без долга рекламы
  `caps-lock` и часы на каждом пакете не берутся. 1 пир — 4.60 против 4.43
  (**+4%**), 5 пиров — паритет.
- Keepalive-таймер больше не снимается на каждой отправке: `timer_delete()`
  в `uwg_timers_any_authenticated_packet_sent()` убран, expiry сравнивает
  `last_data_tx` с `keepalive_armed`. `mod_timer` на 1 пире не изменился —
  источник не keepalive, а `uwg_packet_cwnd_arm_retry()` и TCP. Soak
  (idle 180 с, downlink-only, rekey каждые 15 с, 50 пиров): поведение на
  проводе совпадает с базой, дропов нет. Интерливный A/B 50 пиров —
  **+2.8%** (в пределах ±7%), «только keepalive» — +5.8%. Простой downlink
  по-прежнему шлёт один keepalive за `keepalive_timeout`.
- `gso_segs_max` — `module_param` 1..46, default **44**: A/B на 1 пире 44 →
  4.63, 16 → 4.16–4.33, 8 → 4.41, 2 → 3.34, 1 → 3.74; на 5 пирах 44 → 6.94,
  1 → 5.70. 44 — оптимум на стенде, поведение по умолчанию не изменилось.
- Раздельные пороги `UWG_CRYPT_STEAL_THRESHOLD` (4/32/128 skb) замерены —
  выигрыша нет ни в TX, ни в RX, общее значение 4 оставлено (`queueing.h`).

### UAPI и тесты

- `UWGDEVICE_A_FEC_STATS`/`BBR_STATS` в GET_DEVICE, `UWGDEVICE_A_UNDERLAY_MTU`
  (40), `UWGDEVICE_A_FEC` с проверкой `K=1..8/M=1..2`.
- Init-селфтесты FEC/EXT/BBR/adaptive/MTU проверяют раскладку заголовков,
  бюджет `1340` при `S4=28`, floor `min(576, base)`, квантование,
  пейсинг/ретрай CAPS, отзыв и границы partial-блока `k'`/`m'`.
- Добавлены `tests/fec-partial.sh` и `tests/bbr-ack-gate.sh`.
- Тест потери CAPS в `tests/fec-profile-change.sh` проверяет рост
  `blocks_encoded`/`blocks_decoded` на обеих сторонах после потери пары
  кадров.
- Init-селфтест queueing (`selftest/queueing.c`) — кейсы **1..11**: порог
  stealing, claim/cancel, единственный online-CPU.
- Инициализационные селфтесты проходят кейсы 1..44; выгрузка модуля под
  трафиком — без предупреждений и зависших hrtimer.
- CI: job `fec-profile-change` (смена `2:1`/`8:2`/`off`/`adaptive` на ходу,
  rekey, `-EINVAL`) и профильная регрессия.

## [0.4.0] — 2026-11-20

### Безопасность обфускации

- Нулевой ключ header protection выключает защиту (RCU-указатель NULL).
- Multicast-группа unknown-peer требует `CAP_NET_ADMIN`; уведомления
  ограничены per-device rate limit.
- Окно random trailer ограничено MTU подложки, `DisableCookies` сохраняет
  per-IP rate limit инициаций.

### BBR и FEC

- Счётчики FEC и вложенные атрибуты `UWGDEVICE_A_FEC_STATS`/`BBR_STATS`
  в GET_DEVICE.
- Эпоха keypair в BBR-ринге: смена keypair очищает ring, ACK чужого
  keypair игнорируется.
- `UWGDEVICE_A_UNDERLAY_MTU` (40): при включённом FEC MTU интерфейса
  уменьшается так, чтобы шард помещался в датаграмму, и восстанавливается
  при выключении.
- `cwnd` применяется как ACK-clocked гейт после loss-cut; floor
  `pacing_rate × 5 мс` и аварийный таймаут 5 мс.
- Init-селфтесты расширены (FEC/EXT/BBR), включая adaptive и MTU-бюджет.

## [0.3.0] — 2026-11-20

### BBRv3 и FEC

- CAPS/ACK/FEC_SHARD внутри AEAD-payload (wire-version 1): обмен
  возможностями, ACK с bitmap 64 бита, Reed-Solomon шарды.
- Kernel FEC: систематический RS GF(256) `0x11d`, fixed-профили
  `K=1..8, M=1..2`, adaptive 2:1 с включением при loss > 1% после
  прогрева 1024 пакетов и выключением через 5 с при < 0.2%.
- FEC-TX бюджет в 0.3.0 считался от TUN MTU (`mtu - 50`) без `S4`; в
  0.4.1 он пересчитан от underlay MTU и включает `S4`. Случайный
  `shard_len + 0..31`, случайный порядок шардов, джиттер блока
  `0.5..2 мс` (в 0.4.1 заменён на hrtimer 150–450 мкс).
- Kernel BBR: token-bucket пейсер, Startup/ProbeBW/ProbeRTT, ring 4096,
  loss-сигнал из дыр bitmap/watermark, GSO для FEC-шардов, кэш RS-матрицы,
  header protection под RCU. В 0.3.0 `cwnd` был только телеметрией; с
  0.4.0 он применяется как ACK-clocked гейт после loss-cut.
  `SO_TXTIME`/EDT не используются.
- Netlink: `UWGDEVICE_A_BBR=36` (`u8 0/1/2`) и `UWGDEVICE_A_FEC=37`
  (`0`, `1`, `(K<<8)|M`); неподдерживаемые профили отклоняются `-EINVAL`.

### Обфускация

- Случайный padding control-кадров `0..15`, случайная ACK-каденция
  (`8..16` пакетов или `2..5 мс`), случайный DSCP handshake, хвосты
  FEC-шардов и перемешивание порядка.

### Исправлено

- FEC-таймеры: `timer_shutdown_sync`, флаг `disabled`, корректный порядок
  с `synchronize_net`; устранён UAF при удалении пира.
- CAPS: ограниченное число попыток, ответ только на изменившийся профиль,
  отсутствие пинг-понга; смена `bbr`/`fec` через netlink переотправляет
  CAPS.
- ACK: валидация `largest`/`ack_delay`, ACK-на-ACK исключён, на простое
  ACK не отправляется.
- Приём: `get_unaligned_*` вместо кастов `skb->data`.
- FEC RX: проверка `k/m/index/shard_len`, сброс состояния по keypair,
  ограничение числа блоков.

### Добавлено

- Несколько внешних UDP-потоков на пира: per-device настройка
  `UWGDEVICE_A_EXTRA_PORTS` / `uwg set <if> extra-ports N` / `ExtraPorts`
  в конфиге (0…8, по умолчанию 0 — выключено). Базовый сокет слушает `listen_port`,
  дополнительные — эфемерные; отправка round-robin, приём на всех,
  endpoint roaming. На стенде 3c/10 с RPS `0x34` даёт паритет с `go`
  на obf0 и плюс на obf1.

### Документация

- `docs/UDP-GRO.md`: замеры GRO, прототип в модуле, блокер
  (`udp_gro_receive`/`udp_gro_complete` не экспортируются) и
  предлагаемый патч ядра.

### Добавлено

- Per-peer выбор шифра transport-пакетов: `UWGPEER_A_CIPHER` и
  `enum uwg_cipher` (ChaCha20-Poly1305 по умолчанию, AES-256-GCM).
  AES использует Crypto API `gcm(aes)` (AES-NI/VAES, ARMv8 Crypto
  Extensions, Qualcomm qce) через per-keypair `aead_request`; если
  `gcm(aes)` недоступен, остаётся библиотечный `aes_gcm_*`. На направление
  выделяется пул из четырёх `aead_request`, чтобы крипто-воркеры не
  конкурировали за один request. Handshake, cookie, обфускация и формат
  провода не изменились; один сервер обслуживает пиров с разными шифрами
  одновременно.

## [3.1.20261113-02] — 2026-11-13

Первый релиз UmbraWG (форк AmneziaWG).

### Добавлено

- Поддержка netlink/UAPI UmbraWG 3.1: `H1..H4` (упакованные `u64`-диапазоны),
  `S1..S4`, `Jc/Jmin/Jmax`, `I1..I5`, `HeaderProtectionKey`,
  `ContentPaddingAddition`, диапазоны rekey/keepalive, `RandomTrailers`,
  `DisableCookies`.
- Parity-тесты netlink и интеграционные тесты с живым модулем.
- GSO-агрегация отправки (UDP GSO; стек сегментирует до доставки).
- Per-CPU крипто-очереди, per-peer NAPI, threaded NAPI и коалесинг
  пробуждений (pending-флаг: `queue_work_on` только на переходе 0→1).
- Упаковка: DKMS, `.deb`, `.rpm`, Arch (`-git`), CI-сборка, упаковка и parity.

### Изменено

- Проект переименован AmneziaWG → UmbraWG, `awg` → `uwg`, genl-семейство —
  `umbrawg`.
- Минимальное ядро — Linux 7.x; удалены `compat/` и `zinc`, криптография
  только через in-kernel API (`chacha20poly1305`, `blake2s`, `curve25519`,
  `chacha`).
- Крипто-воркеры распределяют работу round-robin по online-CPU
  (в 0.4.1 заменено на per-CPU enqueue с единым бюджетом, `ae0906c7`).

### Производительность

- +25–33% к `amneziawg` на TCP с одним соединением (1c и 3c), в зависимости
  от обфускации.
- До ~4.95–5.0 Гбит/с суммарно на 4 пирах (3c, 6 vCPU).
- Подробности: [docs/PERFORMANCE.md](docs/PERFORMANCE.md),
  [docs/PEER-SHARDING.md](docs/PEER-SHARDING.md),
  `umbrawg-tools/docs/RESULTS.md`.

### Отклонено

- P0-3 (`get_cpu` вместо round-robin): −12…−26% TCP.
- P0-4 (inline-обработка при пустой очереди): head-of-line, −12…−16% TCP,
  рост UDP-потерь.
- TX-коалесинг: −4…−6% UDP.
- «wire-correct» (одна датаграмма на сообщение): −36…−41%; jumbo-агрегация —
  штатный UDP GSO и interop не ломает.
- Отключение threaded NAPI: −11…−13%.

### Исправлено

- `extra_ports` по умолчанию 0: дополнительные source-порты несовместимы
  с port-restricted NAT (ответы приходили с другого порта, handshake и
  TCP не проходили).
- Счётчики `rx_bytes`/`tx_bytes` пира стали `atomic64_t`, чтобы на
  32-битных ядрах не терять инкременты из нескольких CPU.

- Метаданные упаковки приведены к UmbraWG (URL, Summary, License).
- Версия `3.1.20261113-02` согласована в spec и debian; `debhelper-compat 13`;
  один каталог `/usr/src/umbrawg-3.1.20261113-02`.
