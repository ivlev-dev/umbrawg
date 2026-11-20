# Changelog

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версии соответствуют [SemVer](https://semver.org/lang/ru/).

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
- Self-tests расширены (FEC/EXT/BBR), добавлена KUnit-suite для FEC/ext.

## [0.3.0] — 2026-11-20

### BBRv3 и FEC

- CAPS/ACK/FEC_SHARD внутри AEAD-payload (wire-version 1): обмен
  возможностями, ACK с bitmap 64 бита, Reed-Solomon шарды.
- Kernel FEC: систематический RS GF(256) `0x11d`, fixed-профили
  `K=1..8, M=1..2`, adaptive 2:1 с включением при loss > 1% после
  прогрева 1024 пакетов и выключением через 5 с при < 0.2%.
- FEC-TX бюджет `mtu - 50` (`mtu + 2 - 8 - 12 - 2*16`), случайный
  `shard_len + 0..31`, случайный порядок шардов, джиттер блока
  `0.5..2 мс`. Полноразмерные TCP-сегменты уходят legacy без
  фрагментации.
- Kernel BBR: token-bucket пейсер, Startup/ProbeBW/ProbeRTT, ring 4096,
  loss-сигнал из дыр bitmap/watermark, GSO для FEC-шардов, кэш RS-матрицы,
  header protection под RCU. `cwnd` — телеметрия, к отправке не
  применяется; `SO_TXTIME`/EDT не используются.
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
- Крипто-воркеры распределяют работу round-robin по online-CPU.

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
