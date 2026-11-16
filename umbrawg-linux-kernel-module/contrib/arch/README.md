# Arch Linux / AUR

Каталог содержит AUR-совместимые заготовки пакетов ядерного модуля UmbraWG.
Каждый подкаталог — это содержимое отдельного AUR-репозитория: файлы из него
копируются в корень AUR-репозитория как есть (в AUR `PKGBUILD` обязан лежать
в корне).

| Пакет | Каталог | Тип |
|---|---|---|
| `umbrawg-dkms` | `umbrawg-dkms/` | стабильный, source — архив тега `v3.1.20261113-02` |
| `umbrawg-dkms-git` | `umbrawg-dkms-git/` | VCS, `git+https://github.com/ivlev-dev/umbrawg-linux-kernel-module.git#branch=master` |

Оба пакета ставят только исходники в `/usr/src/umbrawg-<pkgver>`, сборку
выполняет DKMS при установке и при обновлении ядра. Оба конфликтуют друг с
другом: одновременно ставить стабильный и `-git` нельзя.

## Версия

Upstream-версия модуля берётся из `src/version.h` (`UMBRAWG_VERSION`).
В текущем дереве это `3.1.20261113-02`. Дефис в `pkgver` запрещён, поэтому в
`pkgver` он заменён подчёркиванием:

```
UMBRAWG_VERSION 3.1.20261113-02  ->  pkgver 3.1.20261113_02
```

В `umbrawg-dkms-git` к версии из `version.h` добавляется счётчик коммитов и
хэш: `3.1.20261113_02.r12.g1a2b3c4`.

## Что делает `package()`

1. `make dkms-install DESTDIR="$pkgdir" PREFIX=/usr` — цель уже есть в
   `src/Makefile`, она раскладывает `*.c`, `*.h`, `Kbuild`, `Kconfig`,
   `Makefile`, `version.h`, `uapi/` и `dkms.conf` в `/usr/src/umbrawg-<pkgver>`.
2. В установленном `dkms.conf` заменяется `PACKAGE_VERSION` на `pkgver` —
   иначе DKMS искал бы каталог `/usr/src/umbrawg-1.0.0`, а не тот, что создал
   пакет. Замена проверяется, при неудаче сборка пакета падает.
3. В `dkms.conf` дописывается строка `MAKE`:
   `make LLVM=1 UMBRAWG_VERSION=<версия из version.h>`. Без `UMBRAWG_VERSION`
   цель `module` в `src/Makefile` подставляет `1.0.0` из своего умолчания;
   версия из `version.h` точнее. `LLVM=1` соответствует сборке ядра clang/LLD.
   Ключ `CLEAN` не задаётся: dkms 3.x считает его устаревшим и сам очищает
   каталог сборки.

Скрипт `*.install` после установки делает `dkms add/build/install`, при
обновлении сначала снимает старую версию, при удалении — `dkms remove`.
Сообщения об ошибках выводятся, но установка пакета ими не прерывается:
модуль можно собрать позже через `dkms autoinstall` (например, когда
появились `linux-headers`).

## Сборка и проверка

```sh
cd contrib/arch/umbrawg-dkms-git
makepkg -f --nodeps --skipinteg          # пакет без установки
makepkg --printsrcinfo > .SRCINFO        # .SRCINFO для AUR
```

Проверка содержимого пакета:

```sh
bsdtar -xpf umbrawg-dkms-git-*.pkg.tar.zst -C /tmp/pkg
cat /tmp/pkg/usr/src/umbrawg-*/dkms.conf
```

Проверка компиляции модуля из упакованных исходников (DKMS может быть не
установлен, для проверки достаточно заголовков ядра):

```sh
cp -a /tmp/pkg/usr/src/umbrawg-* /tmp/modbuild
cd /tmp/modbuild
make LLVM=1 UMBRAWG_VERSION=3.1.20261113-02 KERNELRELEASE="$(uname -r)"
modinfo umbrawg.ko
```

Проверено на хосте: пакет собирается из дерева, `dkms.conf` содержит
`PACKAGE_VERSION` = `pkgver`, модуль компилируется `make LLVM=1` с
заголовками `7.3.4-1-cachyos-bore-lto`, `modinfo` показывает
`version: 3.1.20261113-02`. Дополнительно проверен полный цикл DKMS без
установки пакета в систему:

```sh
dkms add   -m umbrawg -v <pkgver> --dkmstree /tmp/dkms/lib --sourcetree /tmp/dkms/src
dkms build -m umbrawg -v <pkgver> -k "$(uname -r)" \
    --dkmstree /tmp/dkms/lib --sourcetree /tmp/dkms/src \
    --kernelsourcedir /usr/lib/modules/"$(uname -r)"/build
```

`dkms build` проходит (подпись модуля возможна только от root с настроенным
MOK-ключом). dkms 3.4.5 при этом предупреждает
`Deprecated feature: REMAKE_INITRD` — ключ унаследован из `src/dkms.conf`,
сборке не мешает; при желании upstream может его убрать.

## Публикация в AUR

1. Создать у upstream тег на релизный коммит: `git tag -a v3.1.20261113-02`
   (имя тега = upstream-версия с префиксом `v`, дефис внутри сохраняется).
2. В `umbrawg-dkms/` обновить `pkgver`, `_upstream_version`, `pkgrel`.
3. Пересчитать контрольные суммы стабильного пакета:

   ```sh
   cd contrib/arch/umbrawg-dkms
   updpkgsums
   makepkg --printsrcinfo > .SRCINFO
   ```

4. Скопировать содержимое каталога в корень AUR-репозитория и запушить:

   ```sh
   git clone ssh://aur@aur.archlinux.org/umbrawg-dkms.git
   cp contrib/arch/umbrawg-dkms/{PKGBUILD,umbrawg-dkms.install,.SRCINFO} umbrawg-dkms/
   cd umbrawg-dkms && makepkg --printsrcinfo > .SRCINFO && git add -A
   git commit -m "upgpkg: umbrawg-dkms 3.1.20261113_02-1" && git push
   ```

   Для `umbrawg-dkms-git` копируются `PKGBUILD`, `umbrawg-dkms-git.install`,
   `.SRCINFO`; контрольные суммы там `SKIP` и `updpkgsums` не нужен.

## Допущения и ограничения

- Тегов в репозитории пока нет. Стабильный `PKGBUILD` — корректный шаблон:
  URL архива и каталог распаковки соответствуют тегу
  `v3.1.20261113-02`, но `sha256sums` содержит явную заглушку
  `TODO_UPDPKGSUMS_AFTER_FIRST_TAG` вместо выдуманного хэша. До публикации
  тега пакет намеренно не собирается: запустите `updpkgsums`.
- `arch=('any')` — пакет содержит только исходники, компиляция идёт на
  машине пользователя через DKMS.
- DKMS-сборка требует установленных заголовков ядра (`linux-headers` и
  аналоги); сам пакет их не тянет, чтобы не привязываться к конкретному ядру.
- Собранный модуль проверен только на x86_64 с ядром
  `7.3.4-1-cachyos-bore-lto`; на других ядрах ожидается тот же результат,
  но проверка не проводилась.
- `umbrawg-tools` и `umbrawg-daemon` в AUR — отдельные пакеты, см. их
  `contrib/arch/README.md` в соответствующих репозиториях.
- Для VCS-пакета в репозитории остаётся плейсхолдер `pkgver` (`...r0.g0000000`): `makepkg`
  пересчитывает его функцией `pkgver()` при сборке и переписывает копию `PKGBUILD`;
  закоммиченный `.SRCINFO` содержит плейсхолдер.
