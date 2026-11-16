# UmbraWG tools: Rust

Замена C-утилит `awg`/`awg-quick` (сохранены в `legacy-c/` как эталон поведения и
источник тест-векторов) на Rust.

## Крейты

| Крейт | Ответственность |
|---|---|
| `umbrawg-config` | ключи (base64/hex), модель конфигурации, INI-парсер и эмиттер, параметры обфускации 3.1 |
| `umbrawg-ctl` | управление интерфейсом: kernel netlink (`umbrawg`) и userspace UAPI (`/var/run/umbrawg/<iface>.sock`) |
| `uwg` | CLI: `genkey`, `genpsk`, `pubkey`, `show`, `showconf`, `set`, `setconf`, `--version` |
| `uwg-quick` | `up`, `down`, `strip`, `save` — порт `legacy-c/wg-quick/linux.bash` |

## Правила

- Формат INI и имена ключей совместимы с AmneziaWG 3.1; добавляются только переименованные
  пути (`/etc/umbrawg`) и env-переменные (`UWG_*`).
- Netlink-атрибуты берутся из `netlink-packet-umbrawg`; числовые значения не меняются.
- Выбор транспорта: если интерфейс создан ядром — netlink; иначе UAPI-сокет демона.
- `uwg-quick` вызывает `ip`/`resolvconf`/`sysctl` так же, как bash-версия, и поддерживает
  `UWG_QUICK_USERSPACE_IMPLEMENTATION`.
- Тесты: round-trip INI, тест-векторы ключей, парсинг CLI, `strip` на эталонных конфигах.
