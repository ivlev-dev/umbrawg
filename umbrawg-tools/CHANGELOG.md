# Changelog

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версии соответствуют [SemVer](https://semver.org/lang/ru/).

## [0.2.0] — 2026-11-16

Паритет с legacy-C `awg` и совместимость с модулем ядра UmbraWG 3.1 и
userspace-демоном из `umbrawg-rs`.

### Добавлено

- `uwg addconf <interface> <file>` — дополняет конфигурацию интерфейса:
  `replace_peers` выключен, у каждого пира заменяется список `AllowedIPs`
  (семантика `awg addconf`).
- `uwg syncconf <interface> <file>` — синхронизирует конфигурацию: пиры,
  которых нет в файле, удаляются явно, а общие с работающей конфигурацией
  продолжают сессию (семантика `awg syncconf`, без перезапуска интерфейса).
- `uwg addconf`/`uwg syncconf` работают через оба транспорта: kernel netlink
  и userspace UAPI.
- `uwg show <interface> advanced-security` и строка `advanced security` в
  `uwg show`: ядро отдаёт `UWGPEER_F_HAS_ADVANCED_SECURITY` и
  `UWGPEER_A_ADVANCED_SECURITY`, userspace UAPI поля не имеет и показывает
  `unsupported` без ошибки. В `set` параметр не добавлен.
- Предупреждение в stderr при ненулевых host-битах `AllowedIPs`
  (`Warning: AllowedIP has nonzero host part: …`) для `set`, `setconf`,
  `addconf` и `syncconf`, как в legacy `awg`.
- Позиционные команды `uwg version` и `uwg help` рядом с `--version`/`--help`.
- `uwg-quick`: повторные попытки применения DNS через `resolvconf` (3 попытки
  с паузой 100 мс) и понятная ошибка, если все попытки неудачны.

### Изменено

- `uwg-quick` разбирает конфигурацию через `umbrawg-config`: классификация
  quick-ключей (`QuickKey`), разбор списков (`split_list_value`),
  DNS-адресов (`is_dns_address`) и булевых значений (`parse_bool_value`)
  больше не дублируются; `strip` по-прежнему выдаёт текст байт в байт как
  `wg-quick strip`.
- `uwg-quick save` собирает блок `[Interface]` через INI-эмиттер
  `umbrawg-config`; порядок и формат ключей не изменились.
- `uwg setconf` применяет файл через общий путь `umbrawg-ctl` и так же
  заменяет `AllowedIPs` пиров, у которых в файле нет ключа `AllowedIPs`.
- `umbrawg-ctl`: в модели пира появилось поле `advanced_security`; добавлены
  `ConfigApplication`, `SetDevice::from_config_file`, `SetDevice::synced_from`,
  `umbrawg_ctl::setconf/addconf/syncconf`.
- Версия workspace — `0.2.0`.

### Исправлено

- Пустой список `AllowedIPs` больше не отправляется в netlink как пустой
  вложенный атрибут: достаточно флага `UWGPEER_F_REPLACE_ALLOWEDIPS`.

### CI и упаковка

- Добавлены `rust-ci.yml` (fmt, clippy, тесты workspace) и `rust-build.yml`
  (release-сборки x86_64/aarch64/armv7, артефакты `uwg` и `uwg-quick`,
  релиз по тегу `v*`). Оба workflow клонируют `netlink-packet-umbrawg`
  вторым checkout, поэтому path-зависимость не требует правок `Cargo.toml`.
- Legacy-C workflows переведены в ручной режим и переименованы в `legacy-*`;
  Windows legacy workflow удалён.
- Debian-упаковка и RPM spec переписаны под `cargo build --release`.
- Добавлены man-страницы `uwg(8)`/`uwg-quick(8)`, bash/zsh/fish completions,
  systemd-юниты `uwg-quick@.service`, `uwg-quick.target`, `umbrawg@.service`
  и скрипты `scripts/package/`.

## [0.1.0]

- Первый Rust-порт `awg`/`awg-quick`: `uwg` (`genkey`, `genpsk`, `pubkey`,
  `show`, `showconf`, `set`, `setconf`) и `uwg-quick` (`up`, `down`, `strip`,
  `save`) поверх kernel netlink и userspace UAPI.
