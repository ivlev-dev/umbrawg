# Changelog

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версии соответствуют [SemVer](https://semver.org/lang/ru/).

## [Не выпущено]

### Добавлено

- Per-peer выбор шифра transport-пакетов: `UWGPEER_A_CIPHER` и
  `enum uwg_cipher` (ChaCha20-Poly1305 по умолчанию, AES-256-GCM).
  AES реализован через `aes_gcm_*` (AES-NI, ARMv8 Crypto Extensions,
  GF128HASH/PCLMUL), handshake, cookie, обфускация и формат провода не
  изменились; один сервер обслуживает пиров с разными шифрами одновременно.

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

- Метаданные упаковки приведены к UmbraWG (URL, Summary, License).
- Версия `3.1.20261113-02` согласована в spec и debian; `debhelper-compat 13`;
  один каталог `/usr/src/umbrawg-3.1.20261113-02`.
