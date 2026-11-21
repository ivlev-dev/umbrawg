# Arch Linux / AUR

AUR-совместимые заготовки пакета userspace-демона UmbraWG. Каждый подкаталог —
содержимое отдельного AUR-репозитория: файлы копируются в его корень как есть.

| Пакет | Каталог | Тип |
|---|---|---|
| `umbrawg-daemon` | `umbrawg-daemon/` | стабильный, source — архив тега `rs-v0.4.0` |
| `umbrawg-daemon-git` | `umbrawg-daemon-git/` | VCS, `#branch=master` |

## Состав пакета

- `/usr/bin/umbrawg` — демон (`umbrawg --foreground <iface>`)
- `/usr/lib/systemd/system/umbrawg@.service`
- `/usr/lib/tmpfiles.d/umbrawg.conf` — `d /run/umbrawg 0700 root root -`
- каталог `/etc/umbrawg` (права `0700`)
- лицензия и README в `/usr/share/licenses`, `/usr/share/doc`

Юнит лежит в этом репозитории (`systemd/umbrawg@.service`) и не тянется из
`umbrawg-tools`: пакет `umbrawg-tools` его не устанавливает, чтобы файл не
принадлежал двум пакетам сразу.

`/var/run` в Arch — симлинк на `/run`, поэтому tmpfiles-правило создаёт
`/run/umbrawg`, а UAPI-сокеты демона по умолчанию живут в
`/var/run/umbrawg/<iface>.sock` (см. `umbrawg-uapi`). Кроме tmpfiles каталог
создаёт `RuntimeDirectory=umbrawg` юнита, поэтому правило нужно для запуска
демона вне systemd и для чистки после перезагрузки.

`/etc/umbrawg` — каталог конфигурации (`/etc/umbrawg/<iface>.conf`), его же
использует `uwg-quick` из `umbrawg-tools`. В PKGBUILD это `install -d`, а не
`backup=()`: pacman отслеживает в `backup` только файлы, не каталоги.

## Зависимости

- `depends`: `glibc`, `gcc-libs` (`libgcc_s` нужен Rust-бинарнику).
- `optdepends`: `umbrawg-tools` (`uwg`, `uwg-quick`).
- `makedepends`: `cargo`, `rust`.
- `arch`: `x86_64`, `aarch64` (собрано и проверено только на x86_64).

## Сборка и проверка

```sh
cd contrib/arch/umbrawg-daemon-git
makepkg -f --nodeps --skipinteg
makepkg --printsrcinfo > .SRCINFO

bsdtar -xpf umbrawg-daemon-git-*.pkg.tar.zst -C /tmp/pkg
/tmp/pkg/usr/bin/umbrawg --version
systemd-analyze verify /tmp/pkg/usr/lib/systemd/system/umbrawg@.service
```

`check()` запускает тесты воркспейса и отдельно unit-тесты `umbrawg-uapi`.
Интеграционные тесты `umbrawg-uapi/tests/uapi.rs` требуют root (слушатель
отклоняет `set` от непривилегированного uid с `EACCES`), поэтому в упаковочной
проверке они исключены; полный прогон — `cargo test --workspace` от root.

Проверено на хосте: `umbrawg-daemon-git` собирается из ветки с параллельным RX
(`makepkg -f --nodeps --skipinteg`), `check()` проходит 407 тестов в 23
наборах, `umbrawg 0.4.0` из распакованного пакета печатает версию и справку,
юнит и tmpfiles на месте, `systemd-analyze verify` для `umbrawg@.service`
ошибок не находит (только предупреждение об отсутствии `/usr/bin/umbrawg` в
распакованном дереве), `/etc/umbrawg` — `0700`. Стабильный `umbrawg-daemon` —
шаблон до появления тега `rs-v0.4.0`, в этой проверке не собирался.

## Публикация в AUR

1. Поставить тег `rs-v0.4.0` в `umbrawg-rs`.
2. В `umbrawg-daemon/` обновить `pkgver`/`pkgrel`, затем:

   ```sh
   cd contrib/arch/umbrawg-daemon
   updpkgsums
   makepkg --printsrcinfo > .SRCINFO
   ```

3. Скопировать в корень AUR-репозитория:

   ```sh
   cp contrib/arch/umbrawg-daemon/{PKGBUILD,.SRCINFO} .
   git add -A && git commit -m "upgpkg: umbrawg-daemon 0.4.0-1" && git push
   ```

4. Для `umbrawg-daemon-git` — отдельный AUR-репозиторий, копируются `PKGBUILD`
   и `.SRCINFO`.

## Допущения и ограничения

- Стабильный `PKGBUILD` — шаблон: версия `0.4.0` уже в `Cargo.toml`, а тег
  `rs-v0.4.0` появится при релизе; `sha256sums` содержит явную
  заглушку `TODO_UPDPKGSUMS_AFTER_FIRST_TAG`; после публикации тега суммы
  пересчитываются `updpkgsums`.
- Git-пакет отслеживает `master`; `pkgver` = `0.4.0.r<число коммитов>.g<хэш>`.
- Демону нужны `CAP_NET_ADMIN`, `CAP_NET_RAW` (создание TUN-устройства и
  сокетов); юнит выдаёт их через `AmbientCapabilities`, отдельный пользователь
  не создаётся.
- Сборка идёт по закоммиченному `Cargo.lock` (`cargo fetch --locked` в
  `prepare()`, `cargo build --frozen` в `build()`).
- Для VCS-пакета в репозитории остаётся плейсхолдер `pkgver` (`...r0.g0000000`): `makepkg`
  пересчитывает его функцией `pkgver()` при сборке и переписывает копию `PKGBUILD`;
  закоммиченный `.SRCINFO` содержит плейсхолдер.
