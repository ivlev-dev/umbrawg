# Миграция с AmneziaWG на UmbraWG

Этот гайд описывает переход с AmneziaWG на UmbraWG: что переименовано,
что осталось совместимым, пошаговый порядок действий, подводные камни,
откат и проверочный чек-лист. Гайд относится к набору из четырёх компонентов
UmbraWG: модуль ядра `umbrawg`, Rust-демон `umbrawg`, утилиты `uwg`/`uwg-quick`
и крейт `netlink-packet-umbrawg`.

Общая документация: [README.md](../README.md), [RELEASE.md](../RELEASE.md),
[docs/ARCHITECTURE.md](ARCHITECTURE.md), [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md),
`man/uwg.8`.

## 1. Что переименовано

| Было (AmneziaWG) | Стало (UmbraWG) |
|---|---|
| Проект AmneziaWG | Проект UmbraWG |
| Утилита `awg` | `uwg` |
| Утилита `awg-quick` | `uwg-quick` |
| Go-демон `amneziawg-go` | Rust-демон `umbrawg` (`umbrawg-rs`) |
| Модуль ядра `amneziawg` | Модуль ядра `umbrawg` |
| genl-семейство `amneziawg` | genl-семейство `umbrawg` (`UWG_GENL_NAME = "umbrawg"`) |
| Интерфейсы `awg0`, `awg1`, … | `uwg0`, `uwg1`, … (рекомендация) |
| Пакет `amneziawg-tools` | `umbrawg-tools` (`uwg`, `uwg-quick`) |
| Пакет `amneziawg-dkms` | `umbrawg-dkms` |
| Пакет демона (Go) | `umbrawg-daemon` (Rust) |

См. также раздел «Состав» в [README.md](../README.md) и
[docs/ARCHITECTURE.md](ARCHITECTURE.md) (компоненты и роли).

## 2. Совместимость

Байты на проводе не менялись: Noise IK плюс обфускация 3.1 (junk-пакеты,
magic-заголовки H1–H4, header protection и т. д.). Узел UmbraWG совместим
с узлом AmneziaWG: handshake и передача данных проходят между ними.

Что сохранено:

- **Байты на проводе** — Noise IK + обфускация 3.1 не изменены.
- **Netlink-атрибуты** — надмножество: H1..H4 как u64-диапазоны,
  `AdvancedSecurity` (`UWGPEER_A_ADVANCED_SECURITY`). Номера атрибутов и
  команды (`GetDevice=0`/`SetDevice=1`) те же.
- **UAPI** — Unix-сокет `/var/run/umbrawg/<iface>.sock`, команды `get=1`/`set=1`,
  формат ответов совместим с Go-версией.
- **Конфиг INI** — тот же формат и те же ключи (H1..H4, S1..S4, Jc/Jmin/Jmax,
  I1..I5, `HeaderProtectionKey` и т. д.); `/etc/umbrawg/<iface>.conf`.

Инвариант совместимости зафиксирован в
[docs/ARCHITECTURE.md](ARCHITECTURE.md) (раздел 3): номера netlink-атрибутов
и UAPI-команды не меняются между модулем, демоном и tools.

Ограничения:

- `AdvancedSecurity` реально реализован только в модуле ядра; демон хранит
  поле как информационное и не применяет защиту (см.
  [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md), §5.2).
- Демон обслуживает IPv4-транспорт; IPv6-подложка в него не подключена.

## 3. Порядок миграции (пошагово)

### Шаг 1. Остановить старые сервисы

```sh
sudo awg-quick down awg0
sudo systemctl stop 'amneziawg*' 2>/dev/null || true
sudo pkill -x amneziawg-go 2>/dev/null || true
```

Если есть unit'ы старой установки (`amneziawg@.service`), отключите их:

```sh
sudo systemctl disable --now 'amneziawg@awg0' 2>/dev/null || true
```

### Шаг 2. Установить новые пакеты

Состав пакетов и порядок выпуска — в [RELEASE.md](../RELEASE.md).
Установка из пакетов:

- Debian/Ubuntu:

  ```sh
  sudo apt install ./dist/umbrawg-tools_*.deb
  sudo apt install ./dist/umbrawg-dkms_*.deb   # если есть
  ```

- Fedora/RHEL:

  ```sh
  sudo dnf install ./dist/umbrawg-tools-*.rpm
  ```

- Arch:

  ```sh
  sudo pacman -U ./umbrawg-tools-*.pkg.tar.zst
  ```

DKMS-модуль требует заголовков ядра и toolchain (см.
[docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md), §3.3). Требования к ядру —
Linux 7.0+ (см. §4).

Для ручной сборки из исходников нужен соседний репозиторий
`netlink-packet-umbrawg` (path-зависимость Cargo) — см.
[README.md](../README.md), раздел «Упаковка» и «Сборка в Docker».

### Шаг 3. Перенести конфиги

```sh
sudo install -d -m 0700 /etc/umbrawg
sudo cp /etc/amneziawg/*.conf /etc/umbrawg/
sudo chmod 700 /etc/umbrawg
sudo chown root:root /etc/umbrawg /etc/umbrawg/*.conf
```

Ключи, пиры и параметры обфускации остаются теми же. Проверьте:

- `AdvancedSecurity` (если использовался) — на демоне это информационное поле;
  для реальной защиты нужен модуль ядра на обеих сторонах.
- host-биты/MTU в конфиге: `MTU` при необходимости задайте явно (см. §4).
- имена интерфейсов: рекомендуется перейти на `uwg0`, `uwg1`, …; при сохранении
  старых имён `awg0` конфиги и сервисы продолжат работать, но именование будет
  смешанным.

### Шаг 4. Поднять userspace-демон, затем ядро

Порядок важен: первый handshake теряется, если ядро стартует раньше демона
(см. [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md), §1.1).

1. Поднять и сконфигурировать демон на принимающей стороне:

   ```sh
   sudo systemctl start umbrawg@uwg0
   sudo uwg setconf uwg0 /etc/umbrawg/uwg0.conf
   ss -lunp | grep 51820
   ```

2. Убедиться, что демон слушает UDP-порт, и только затем настраивать сторону
   с модулем ядра:

   ```sh
   sudo ip link add dev uwg0 type umbrawg
   sudo uwg setconf uwg0 /etc/umbrawg/uwg0.conf
   ```

Если обе стороны на одном хосте, не поднимайте модуль и демон с одним именем
интерфейса: TUN демона и netdev модуля не могут занимать одно имя.

### Шаг 5. Проверить туннель

```sh
uwg show uwg0 latest-handshakes
uwg show uwg0 transfer
uwg show uwg0 endpoints
ping -c 3 10.0.0.2
```

Ожидаемо: время handshake близко к `date +%s` (не `0`), endpoint не `(none)`,
ping проходит. Счётчики `transfer` растут. Сравните MTU и underlay (см. §4).

### Шаг 6. Включить сервисы и удалить старые пакеты

```sh
sudo systemctl enable --now umbrawg@uwg0
sudo systemctl enable --now 'uwg-quick@uwg0' 2>/dev/null || true
```

После успешной проверки удалите старые пакеты (`amneziawg-tools`,
`amneziawg-dkms`, `amneziawg-go`) через пакетный менеджер. Храните резервную
копию `/etc/amneziawg` до завершения проверки.

## 4. Подводные камни

- **Linux 7.x для модуля.** UmbraWG требует Linux 7.0+; для ядра, собранного
  clang (CachyOS, часть Fedora), обязателен `make LLVM=1`. См.
  [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md), §3.1.
- **MTU/S4/underlay.** Junk/padding/trailers увеличивают датаграмму:
  `TUN_MTU ≤ UNDERLAY_MTU - (80 + S4)` (`OVERHEAD_BASE = 80`).
  `uwg-quick` при отсутствии `MTU` считает `MTU = MTU маршрута − 80` и не
  учитывает `S4`; для профиля с `S4=28` задайте `MTU = 1380` (или ниже) в
  `[Interface]`. См. [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md), §2.1.
- **rmem_max / UMBRAWG_SOCKET_BUFFER.** Демон запрашивает буфер сокета
  `UMBRAWG_SOCKET_BUFFER` (по умолчанию 4 МиБ); ядро урезает до
  `net.core.rmem_max`/`wmem_max`. Поднимите лимиты или уменьшите переменную.
  См. [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md), §2.3.
- **AdvancedSecurity в userspace — informational.** Реализован только в модуле
  ядра; на демоне флаг хранится и отражается, но не применяется.
- **Разные имена unit'ов systemd.** В tools поставляются `uwg-quick@.service`,
  `uwg-quick.target`, `umbrawg@.service`; в Arch юнит `umbrawg@.service`
  принадлежит пакету `umbrawg-daemon`. Проверяйте фактический unit и владельца
  пакета (см. [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md), §4.5).
- **Path-зависимость упаковки.** Тарбол содержит два дерева рядом
  (`umbrawg-tools` и `netlink-packet-umbrawg`), т. к. Cargo-зависимость задана
  относительным путём. См. [README.md](../README.md), «Упаковка».
- **Параллельный RX не включать без необходимости.** `UMBRAWG_PARALLEL_RX=1`
  экспериментален и на одном пире медленнее обычного режима. См.
  [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md), §6.

## 5. Откат

Вернуться на AmneziaWG можно в любой момент: форматы совместимы.

1. Остановить новые сервисы:

   ```sh
   sudo systemctl stop 'umbrawg@*' 'uwg-quick@*' 2>/dev/null || true
   sudo uwg-quick down uwg0 2>/dev/null || true
   ```

2. Вернуть конфиги (из резервной копии `/etc/amneziawg` или скопировав
   обратно):

   ```sh
   sudo cp /etc/umbrawg/*.conf /etc/amneziawg/ 2>/dev/null || true
   ```

3. Установить старые пакеты (`amneziawg-tools`, `amneziawg-dkms`,
   `amneziawg-go`) и удалить новые (`umbrawg-tools`, `umbrawg-dkms`,
   `umbrawg-daemon`).

4. Поднять старые сервисы:

   ```sh
   sudo awg-quick up awg0
   sudo systemctl start 'amneziawg@awg0' 2>/dev/null || true
   ```

Конфиги и ключи не требуют преобразования: INI-формат и параметры обфускации
совместимы в обе стороны. Если вы переименовали интерфейсы в `uwg0`, верните
имена `awg0` (или оставьте `uwg0` — AmneziaWG использует те же соглашения
именования интерфейсов, но unit'ы/скрипты старой установки ожидают `awg0`).

## 6. Проверочный чек-лист

| Шаг | Команда | Ожидаемый результат |
|---|---|---|
| Старые сервисы остановлены | `pgrep -a amneziawg-go; systemctl is-active 'amneziawg*'` | процессов нет / inactive |
| Новые пакеты установлены | `uwg --version; modinfo umbrawg \| grep ^version` | версия печатается; модуль найден |
| Конфиг перенесён | `ls -l /etc/umbrawg/*.conf; stat -c '%a' /etc/umbrawg` | файлы есть; права `700` |
| Демон слушает порт | `ss -lunp \| grep 51820` | UDP-сокет присутствует |
| Интерфейс создан | `ip -d link show dev uwg0` | `kind umbrawg` (ядро) или `kind tun` (демон) |
| Handshake прошёл | `uwg show uwg0 latest-handshakes` | время близко к `date +%s`, не `0` |
| Endpoint задан | `uwg show uwg0 endpoints` | адрес, не `(none)` |
| Передача идёт | `uwg show uwg0 transfer` | rx/tx растут |
| Ping через туннель | `ping -c 3 10.0.0.2` | 0% потерь |
| MTU согласован | `ip link show dev uwg0` | MTU ≤ underlay − 80 − S4 |
| Сервис включён | `systemctl is-enabled umbrawg@uwg0` | `enabled` |
| Старые пакеты удалены | `pacman -Q amneziawg-tools 2>/dev/null; dpkg -l \| grep amneziawg` | не найдены |

Дополнительные проверки (MTU/фрагментация, буферы, логи) — в
[docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md), разделы 2 и 7.
