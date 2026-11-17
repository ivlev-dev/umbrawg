# Changelog

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версии соответствуют [SemVer](https://semver.org/lang/ru/).

## [Не выпущено]

### Добавлено

- `AdvancedSecurity` пира передаётся в userspace UAPI: `uwg set` и
  `uwg setconf`/`addconf`/`syncconf` отправляют `advanced_security=1|0`
  (явный `off` — это `0`, отсутствие ключа в файле — ключ не отправляется).
  Демон сохраняет и возвращает значение (`reported`), но не применяет его.
- `uwg show`, `uwg show <iface> advanced-security` и `showconf` показывают
  состояние из userspace UAPI как `yes`/`no` и `AdvancedSecurity = on|off`;
  `unsupported`/отсутствие строки остаются для интерфейсов, которые ключ
  не отдают. Формат kernel-пути не изменился.

### Изменено

- `uwg` больше не предупреждает, что `AdvancedSecurity` поддерживает только
  ядро: ключ теперь проходят через userspace UAPI без ошибок и предупреждений.
- `uwg` и `uwg-quick` возвращают код 1 при ошибках использования (неизвестная
  команда или параметр, отсутствующий либо лишний аргумент) и печатают usage
  в stderr, как legacy `wg`/`awg`; раньше `uwg` (clap) завершался с кодом 2.
  `--help`/`-h`/`help` и `--version`/`-v`/`version` по-прежнему завершаются
  с кодом 0; если после такого флага указан лишний аргумент, это ошибка
  использования (код 1), как в legacy `wg`.
- `uwg -v` работает как короткий алиас `--version`, как в legacy `wg`;
  `uwg -V` больше не принимается.
- `uwg show <interface> <неизвестный параметр>` печатает usage после сообщения
  `Invalid parameter`, как legacy `wg show`.

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
- `AdvancedSecurity` пира читается из `[Peer]` и параметра
  `uwg set … peer … advanced-security <on|off>` (регистронезависимо,
  `on`/`off`/`true`/`false`/`1`/`0`, как в legacy `awg`), печатается в
  `showconf` и сохраняется `uwg-quick save`. Через kernel netlink значение
  передаётся типизированным `UWGPEER_A_ADVANCED_SECURITY` только для `on`;
  userspace UAPI такого ключа не знает, поэтому `uwg` предупреждает и
  не отправляет его, не прерывая `setconf`/`addconf`/`syncconf`.
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

- `uwg-quick up` передаёт конфигурацию в `uwg setconf` как файл
  (`/dev/stdin`): раньше команда запускалась без обязательного аргумента
  `<configuration filename>` и падала с usage-ошибкой.
- `uwg show <interface> max_handshake_attempts` (форма из legacy `awg show`)
  принимается наравне с `max-handshake-attempts` и опечаткой
  `max-handshake-attemps`.
- `uwg-quick strip` больше не требует root: `sudo` запускается только для
  `up`, `down` и `save`, как в legacy `wg-quick`.
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
- `.deb` и `.rpm` собраны и проверены в контейнерах (`debian:trixie`,
  `rust:1.85-bookworm`, `debian:bookworm`, `fedora:latest`): установка,
  `uwg --version`, smoke-скрипт `debian/tests/smoke`, man-страницы,
  completions, systemd-юниты и `/etc/umbrawg` с правами `0700`.
- `build-deb.sh` при отсутствии `Build-Depends` в виде пакетов (rustup-образы)
  проверяет `cargo`/`rustc` из `PATH` и версию `rustc` против `rust-version`,
  после чего добавляет `dpkg-buildpackage -d`.
- Добавлены `debian/umbrawg-tools.lintian-overrides` для `/lib/systemd/system`
  (merged-/usr) и режима `0700` у `/etc/umbrawg`; в README описана сборка
  пакетов в Docker.

## [0.1.0]

- Первый Rust-порт `awg`/`awg-quick`: `uwg` (`genkey`, `genpsk`, `pubkey`,
  `show`, `showconf`, `set`, `setconf`) и `uwg-quick` (`up`, `down`, `strip`,
  `save`) поверх kernel netlink и userspace UAPI.
