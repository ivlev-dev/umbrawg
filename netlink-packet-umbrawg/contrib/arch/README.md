# Arch Linux / AUR

AUR-совместимые заготовки пакета Rust-крейта `netlink-packet-umbrawg`.
Каждый подкаталог — содержимое отдельного AUR-репозитория: файлы копируются в
его корень как есть.

| Пакет | Каталог | Тип |
|---|---|---|
| `rust-netlink-packet-umbrawg` | `rust-netlink-packet-umbrawg/` | стабильный, source — архив тега `v0.3.0` |
| `rust-netlink-packet-umbrawg-git` | `rust-netlink-packet-umbrawg-git/` | VCS, `#branch=main` |

## Зачем пакет

Крейт — библиотека, бинарников не содержит. Пакет нужен как build-зависимость
для `umbrawg-tools` и других Rust-проектов, собираемых на Arch с подменой
реестра crates.io на локальный каталог. Поэтому `arch=('any')` и
`package()` только раскладывает исходники:

```
/usr/share/cargo/registry/netlink-packet-umbrawg-<version>/
    Cargo.toml
    README.md
    CHANGELOG
    LICENSE
    src/*.rs
    .cargo-checksum.json
/usr/share/licenses/rust-netlink-packet-umbrawg/LICENSE
```

`.cargo-checksum.json` создаётся с содержимым `{"files":{},"package":null}`:
крейта нет на crates.io, поэтому сверять нечего, а каталог-реестр cargo без
этого файла не читает.

Версия каталога — версия из `Cargo.toml` крейта, а не `pkgver` пакета: у
`-git`-пакета `pkgver` выглядит как `0.3.0.r12.g1a2b3c4`, и такой суффикс не
является корректной semver-версией, с которой cargo умеет сопоставлять
зависимость `netlink-packet-umbrawg = "0.3"`. Поэтому для `-git` каталог
называется по версии из `Cargo.toml` (сейчас `0.3.0`).

## Использование

Подмена источника (стандартная для Arch схема, если не установлен
`rustup`-реестр):

```toml
# /etc/cargo/config.toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "/usr/share/cargo/registry"
```

Дальше в проекте достаточно `netlink-packet-umbrawg = "0.3"`.

`provides`/`conflicts` не объявляются: пакет не подменяет другой пакет и не
конфликтует с ним, имя совпадает с именем крейта. Две версии между собой
конфликтуют (`rust-netlink-packet-umbrawg` vs `-git`), одновременно ставить их
нельзя.

## Сборка и проверка

```sh
cd contrib/arch/rust-netlink-packet-umbrawg-git
makepkg -f --nodeps --skipinteg
makepkg --printsrcinfo > .SRCINFO

bsdtar -xpf rust-netlink-packet-umbrawg-git-*.pkg.tar.zst -C /tmp/pkg
ls /tmp/pkg/usr/share/cargo/registry/netlink-packet-umbrawg-*/
```

Проверка, что cargo действительно собирает зависимость из такого каталога:
создать тестовый проект с `netlink-packet-umbrawg = "0.3"`,
`[source.crates-io] replace-with = "vendored-sources"`,
`directory = .../usr/share/cargo/registry` и выполнить `cargo build --offline`.
Проверено на хосте: пакет собирается, `cargo` находит крейт в каталоге-реестре
и компилирует пример, использующий `UmbrawgMessage`.

## Публикация в AUR

1. Поставить тег `v0.3.0`.
2. В `rust-netlink-packet-umbrawg/` обновить `pkgver`/`pkgrel`, затем:

   ```sh
   cd contrib/arch/rust-netlink-packet-umbrawg
   updpkgsums
   makepkg --printsrcinfo > .SRCINFO
   ```

3. Скопировать в корень AUR-репозитория:

   ```sh
   cp contrib/arch/rust-netlink-packet-umbrawg/{PKGBUILD,.SRCINFO} .
   git add -A && git commit -m "upgpkg: rust-netlink-packet-umbrawg 0.3.0-1" && git push
   ```

4. Для `rust-netlink-packet-umbrawg-git` — отдельный AUR-репозиторий,
   копируются `PKGBUILD` и `.SRCINFO`.

## Допущения и ограничения

- Стабильный `PKGBUILD` — шаблон: тегов пока нет, `sha256sums` содержит явную
  заглушку `TODO_UPDPKGSUMS_AFTER_FIRST_TAG`, суммы пересчитываются
  `updpkgsums` после публикации тега.
- В пакет попадают только `Cargo.toml`, `src/`, `README.md`, `CHANGELOG`,
  `LICENSE` и `.cargo-checksum.json`; `tests/`, `examples/`, `fuzz/`,
  `scripts/` не нужны для сборки зависимости и не устанавливаются.
- Файл `LICENSE` добавлен в этот репозиторий в рамках упаковки: README уже
  ссылался на `./LICENSE`, но файла не было, а AUR требует установки лицензии.
  Строку copyright при необходимости уточнить у владельца проекта.
- Крейт использует `netlink-packet-generic` и `netlink-packet-core` из
  crates.io; для офлайновой сборки потребителю нужны соответствующие
  `rust-*` пакеты или собственный vendor-каталог.
- Для VCS-пакета в репозитории остаётся плейсхолдер `pkgver` (`...r0.g0000000`): `makepkg`
  пересчитывает его функцией `pkgver()` при сборке и переписывает копию `PKGBUILD`;
  закоммиченный `.SRCINFO` содержит плейсхолдер.
