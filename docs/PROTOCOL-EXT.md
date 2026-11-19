# UmbraWG protocol extension: feedback, BBRv3 и FEC

Статус: черновик для реализации в Rust (этап 1). Совместимость с
AmneziaWG/UmbraWG 3.1 сохраняется: handshake и формат transport-пакета не
меняются, новые сообщения едут внутри обычного AEAD-payload.

## 1. Маркер и виды сообщений

Внутри расшифрованного transport-payload первым байтом идёт маркер.
Валидный внутренний IP-пакет всегда начинается с version nibble 4 или 6,
поэтому `0x00` однозначно отличает extension.

```
offset  size  field
0       1     0x00
1       3     "UWG" (0x55 0x57 0x47)
4       1     version = 1
5       1     kind: 1=CAPS, 2=ACK, 3=FEC_SHARD
6       2     payload_len, little-endian
8       ...   payload
```

Если маркер не совпал, payload считается обычным IP-пакетом. Пир, не
поддерживающий extension, получает такой пакет как «IP version 0» и
отбрасывает его на уровне TUN/IP-стека; данные не затрагиваются.

## 2. CAPS (kind = 1)

Payload 12 байт:

```
0   u32 flags: bit0 BBR, bit1 ACK, bit2 FEC, bit3 FEC_ADAPTIVE
4   u16 ack_interval_packets (0 = 2)
6   u8  fec_k
7   u8  fec_m
8   u32 reserved = 0
```

Обмен: после установления keypair и при включённой локальной функции
отправить CAPS; повторять не чаще раза в 2 с, максимум 3 раза, пока не
получен CAPS от пира. Возможности пира — пересечение с локальными.
BBR включается, только если у пира установлен bit1 (ACK); FEC — только
если bit2.

## 3. ACK (kind = 2)

Payload:

```
0   u64 largest_counter          максимальный полученный counter
8   u32 ack_delay_us             задержка между приёмом largest и отправкой ACK
12  u8  flags: bit0 ECN-CE
13  u8  bitmap_len (1..8)
14  u16 reserved = 0
16  ... bitmap                    bit0 = largest_counter, bit i = largest-i
```

- Bitmap обновляется при успешной аутентификации transport-пакета и при
  восстановлении FEC-шарда (восстановленный counter помечается как
  полученный, чтобы BBR не считал его потерей).
- ACK отправляется каждые `ack_interval` пакетов, при обнаружении gap и не
  реже раза в 1 мс. Сам ACK — обычный transport-пакет со своим counter.
- При смене keypair трекер сбрасывается; counter начинается с 0.
- Bitmap 64 бита достаточен для окна 64 пакетов; при большем разрыве
  отправляется ACK с новым largest и пустыми битами.

## 4. FEC_SHARD (kind = 3)

Payload:

```
0   u32 block_id                на пира и направление, wrap-around
4   u8  index                   0..k+m-1
5   u8  k                       число data-шардов
6   u8  m                       число parity-шардов
7   u8  flags: bit0 parity
8   u16 shard_len               длина payload каждого шарда
10  u16 reserved = 0
12  ... shard payload            shard_len байт
```

Data-шард внутри payload: `u16 packet_len`, байты IP-пакета, нулевой
padding до `shard_len`. Parity-шард: m байт RS над data-шардами.

- Reed-Solomon над GF(256), систематический, `k+m <= 255`, `k >= 1`,
  `m >= 1`. Полином 0x11d, матрица Вандермонда; таблицы log/exp
  детерминированы и совпадают в Rust и ядре.
- Размер шарда фиксирован на блок: `shard_len = max(2 + len(packet))` по
  пакетам блока. Если `20 + shard_len + TAG_LEN + TUNNEL_HEADER` превышает
  outer MTU, пакет отправляется обычным (legacy) путём и в блок не входит.
- Sender копит до `k` пакетов; flush по `k` или таймауту (по умолчанию
  1 мс). Если на таймауте меньше `k`, отправляются только data-шарды
  (parity не добавляется).
- Receiver хранит блоки, при наличии `k` из `k+m` восстанавливает
  потерянные data-шарды, отдаёт пакеты в порядке `block_id`, затем
  `index`. Таймаут блока (по умолчанию 5 мс) отдаёт всё, что есть, без
  восстановления. Блоки с пропущенным `block_id` ждут не дольше таймаута.
- Адаптивный режим: `m` вычисляется по pre-FEC loss из ACK (доля
  потерянных transport-пакетов). При loss < 0.5% FEC выключается
  (обычные IP-payload без заголовков и padding). Гистерезис: включать при
  loss > 1%, выключать при loss < 0.2% в течение 5 секунд. `m` ограничен
  1..16, `k` по умолчанию 10.

Порядок байт — little-endian, как в остальном протоколе.

## 5. BBRv3

Реализуется как sender-side congestion control для outer UDP-потока:

- Вход: ACK (largest, bitmap, delay), длины отправленных пакетов, время
  отправки; выход: pacing rate (bytes/s), cwnd (bytes), in-flight лимит.
- Модель: BtlBw (окно max delivery rate), RTprop (min RTT, окно 10 с),
  round-детекция по delivered, режимы STARTUP / DRAIN / PROBE_BW /
  PROBE_RTT, v3-параметры: startup gain 2.77, cwnd gain 2, цикл
  [1.25, 0.75, 1, 1, 1, 1, 1, 1], inflight_hi/lo, loss threshold 2%.
- Потери, восстановленные FEC, в ACK помечены как полученные и не
  считаются congestion-loss. Реальная потеря (gap после таймаута FEC)
  учитывается для inflight_hi/lo.
- Pacing в Rust: token bucket + `SO_TXTIME`/ETF, если доступен, иначе
  расчёт задержки и `poll`/sleep на батч; в ядре — EDT/fq.
- По умолчанию выключен; режимы `off | monitor | on` (monitor считает
  оценки и пишет статистику, но не меняет отправку).
- Внутренний протокол не анализируется: BBR/FEC работают с любыми
  IP-пакетами (TCP/UDP/ICMP/...).

## 6. Конфигурация

- UAPI/конфиг: `bbr = off|monitor|on`, `fec = off|adaptive|K:M`.
- Netlink (ядро): новые атрибуты добавляются на этапе порта; до этого
  поля живут в UAPI-демоне.
- `off` — строго нулевые накладные расходы: ни CAPS, ни ACK, ни
  заголовков, ни padding.

## 7. Совместимость

- Старый пир: extension-пакеты выглядят как невалидный IP и
  отбрасываются; handshake и данные не ломаются. После трёх CAPS без
  ответа функции отключаются для пира.
- Смешанный стек: BBR и FEC включаются независимо; ACK используется
  только если обе стороны его понимают.
- Wire-format handshake, cookie, обфускация и существующий transport
  header не меняются.
