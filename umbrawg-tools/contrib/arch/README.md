# Arch Linux / AUR

AUR-совместимые заготовки пакетов CLI UmbraWG. Каждый подкаталог — содержимое
отдельного AUR-репозитория: файлы копируются в его корень как есть.

| Пакет | Каталог | Тип |
|---|---|---|
| `umbrawg-tools` | `umbrawg-tools/` | стабильный, source — архивы тегов `v0.2.0` (tools) и `v0.3.0` (netlink) |
| `umbrawg-tools-git` | `umbrawg-tools-git/` | VCS, `#branch=master` (tools) + `#branch=main` (netlink) |

## Состав пакета

- `/usr/bin/uwg`, `/usr/bin/uwg-quick`
- `/usr/share/man/man8/uwg.8.gz`, `uwg-quick.8.gz`
- bash/zsh/fish-автодополнения из `completions/`
- `/usr/lib/systemd/system/uwg-quick@.service`, `uwg-quick.target`
- каталог `/etc/umbrawg` (права `0700`) для `INTERFACE.conf`

Юнит `umbrawg@.service` в пакет `umbrawg-tools` **не входит**: он относится к
демону и устанавливается пакетом `umbrawg-daemon`. Иначе оба пакета владели бы
одним и тем же файлом и pacman не дал бы установить их вместе.

## Зависимости

- `depends`: `glibc`, `gcc-libs` (`libgcc_s` нужен Rust-бинарникам),
  `iproute2` (`uwg-quick` вызывает `ip`).
- `optdepends`: `nftables`/`iptables` (firewall-правила `uwg-quick`),
  `openresolv`/`systemd-resolvconf` (DNS через `resolvconf`), `procps-ng`
  (`sysctl`), `umbrawg-dkms` (ядерный бэкенд), `umbrawg-daemon`
  (userspace-бэкенд).
- `makedepends`: `cargo`, `rust`.
- `arch`: `x86_64`, `aarch64` (собрано и проверено только на x86_64).

## Сборка `uwg`/`uwg-quick` из двух архивов

`Cargo.toml` воркспейса содержит path-зависимость
`netlink-packet-umbrawg = { path = "../netlink-packet-umbrawg" }`. Чтобы она
разрешалась, в `$srcdir` должны лежать оба дерева, причём каталог netlink обязан
называться ровно `netlink-packet-umbrawg`:

- `umbrawg-tools-git`: оба source — git-репозитории, имя каталога задаётся
  префиксом `netlink-packet-umbrawg::git+...`, поэтому path-зависимость
  работает без правок.
- `umbrawg-tools`: архивы распаковываются в
  `umbrawg-tools-0.2.0/` и `netlink-packet-umbrawg-0.3.0/`; в `prepare()`
  создаётся симлинк `$srcdir/netlink-packet-umbrawg` на распакованный каталог
  netlink. Исходники и `Cargo.toml` при этом не правятся.

Дальше сборка идёт обычным cargo:

```sh
cargo fetch --locked
cargo build --release --frozen --package uwg --package uwg-quick
cargo test  --release --frozen --workspace     # check()
```

`--frozen` = `--locked --offline`: зависимости скачиваются на шаге `prepare()`,
сборка воспроизводима по закоммиченному `Cargo.lock` (`--skipinteg` при
локальной проверке не обязателен, суммы VCS-пакета — `SKIP`).

## Сборка и проверка

```sh
cd contrib/arch/umbrawg-tools-git
makepkg -f --nodeps --skipinteg
makepkg --printsrcinfo > .SRCINFO

bsdtar -xpf umbrawg-tools-git-*.pkg.tar.zst -C /tmp/pkg
/tmp/pkg/usr/bin/uwg --version
/tmp/pkg/usr/bin/uwg-quick --help
ldd /tmp/pkg/usr/bin/uwg
```

Проверено на хосте: `umbrawg-tools-git` собирается из деревьев tools `0.2.0`
и netlink `0.3.0` (`makepkg -f --nodeps --skipinteg`), `check()` проходит
212 тестов в 12 наборах, `uwg v0.2.0` и `uwg-quick --help` запускаются из
распакованного пакета, man-страницы проходят `gzip -t` и `groff -man`,
автодополнения — `bash -n` и `fish -n`, `systemd-analyze verify` для
`uwg-quick@.service` и `uwg-quick.target` ошибок не находит (только
предупреждение об отсутствии `/usr/bin/uwg-quick` в распакованном дереве),
права на `/etc/umbrawg` — `0700`. `makepkg` предупреждает, что `usr/bin/uwg`
содержит строки с `$srcdir` (panic-локации Rust); на работу пакета это не
влияет. Стабильный `umbrawg-tools` — шаблон до появления тегов, в этой
проверке не собирался.

## Публикация в AUR

1. Поставить теги: `v0.2.0` в `umbrawg-tools`, `v0.3.0` в
   `netlink-packet-umbrawg` (без тега netlink не соберётся стабильный пакет).
2. В `umbrawg-tools/` при необходимости обновить `pkgver`, `_netlink_ver`,
   `pkgrel`, затем:

   ```sh
   cd contrib/arch/umbrawg-tools
   updpkgsums
   makepkg --printsrcinfo > .SRCINFO
   ```

3. Проверить dry-run и опубликовать:

   ```sh
   scripts/aur-publish.sh umbrawg-tools --source-root .
   scripts/aur-publish.sh umbrawg-tools --source-root . --push
   ```

   Скрипт клонирует AUR-репозиторий, копирует `PKGBUILD`, `*.install` и
   `.SRCINFO`, коммитит `Update to <pkgver>-<pkgrel>` и пушит. Подробности —
   раздел «Публикация в AUR» в [README.md](../../README.md).

4. Для `umbrawg-tools-git` — отдельный AUR-репозиторий, копируются `PKGBUILD`
   и `.SRCINFO` (суммы `SKIP`, `updpkgsums` не нужен).

## Допущения и ограничения

- Стабильный `PKGBUILD` — шаблон: тегов пока нет, `sha256sums` содержит явную
  заглушку `TODO_UPDPKGSUMS_AFTER_FIRST_TAG` (не выдуманный хэш). После
  публикации тегов суммы пересчитываются `updpkgsums`.
- `-git`-пакет собирается из `master` tools и `main` netlink; `pkgver` =
  `0.2.0.r<число коммитов>.g<хэш>`.
- Каталог `contrib/arch` — место хранения в исходном репозитории; AUR требует
  `PKGBUILD` в корне своего репозитория, поэтому файлы копируются.
- `check()` прогоняет тесты воркспейса без root; интеграционные тесты, которым
  нужен настоящий модуль ядра, в пакет не входят.
- Для VCS-пакета в репозитории остаётся плейсхолдер `pkgver` (`...r0.g0000000`): `makepkg`
  пересчитывает его функцией `pkgver()` при сборке и переписывает копию `PKGBUILD`;
  закоммиченный `.SRCINFO` содержит плейсхолдер.
