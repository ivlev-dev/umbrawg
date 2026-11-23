# Выпуск UmbraWG

Единый чек-лист для монорепозитория `ivlev-dev/umbrawg`. Версия `0.5.1` —
релизная (2026-11-21); теги `*-v0.5.0` ставятся отдельно и строго по
порядку из раздела «Порядок тегов».

## Компоненты, версии и теги

| Компонент | Каталог | Манифест версии | Пакеты | Тег |
|---|---|---|---|---|
| netlink | `netlink-packet-umbrawg/` | `Cargo.toml` | `netlink-packet-umbrawg`, `rust-netlink-packet-umbrawg` | `netlink-v0.5.0` |
| tools | `umbrawg-tools/` | `Cargo.toml` | `uwg`, `uwg-quick`, `umbrawg-tools` | `tools-v0.5.0` |
| daemon | `umbrawg-rs/` | `Cargo.toml` | `umbrawg`, `umbrawg-daemon` | `rs-v0.5.0` |
| kernel | `umbrawg-linux-kernel-module/` | `src/version.h` | DKMS-модуль `umbrawg` | `kernel-v0.5.0` |

Теги **всегда** с префиксом компонента (`kernel-v*`, `netlink-v*`,
`tools-v*`, `rs-v*`) — так устроены `paths`/`tags`-фильтры CI и
`*-packaging.yml`. Голый `v0.5.0` больше не используется: он остался только
у исторического `v0.1.0`.

Каноническая строка версии модуля — `0.5.0`. Пакетные менеджеры нормализуют
её: Arch и RPM используют `0.5.0`, Debian — upstream `0.5.0` с epoch
(`1:0.5.0-1`). `modinfo` показывает `0.5.0`.

## Порядок тегов

Теги ставятся и пушатся строго по порядку:

1. `netlink-v0.5.0` — `netlink-packet-umbrawg/`.
2. `tools-v0.5.0` — `umbrawg-tools/` (зависит от netlink 0.5.0 и его lock).
3. `rs-v0.5.0` — `umbrawg-rs/`.
4. `kernel-v0.5.0` — `umbrawg-linux-kernel-module/`.

Причина: `umbrawg-tools/Cargo.lock` собран против `netlink-packet-umbrawg`
0.5.0. Если сначала выпустить tools, CI возьмёт netlink из `master` со старой
версией и `cargo fetch --locked` упадёт. Стабильные PKGBUILD ссылаются на
архивы тегов, поэтому `updpkgsums` и публикация в AUR — только после того,
как все четыре тега запушены.

```sh
git tag netlink-v0.5.0 && git push origin netlink-v0.5.0
git tag tools-v0.5.0   && git push origin tools-v0.5.0
git tag rs-v0.5.0      && git push origin rs-v0.5.0
git tag kernel-v0.5.0  && git push origin kernel-v0.5.0
```

Тег модуля обязан совпадать с `UMBRAWG_VERSION` в `src/version.h`: job
`meta` в `kernel-packaging.yml` падает, если `kernel-v*` не равен версии из
манифеста. То же для `netlink-v*`, `tools-v*`, `rs-v*` и их `Cargo.toml`.

## Перед тегом

```sh
# netlink
cd netlink-packet-umbrawg
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo +nightly fmt --all -- --check
bash scripts/check-uapi-parity.sh          # сверка с UAPI-заголовком модуля

# tools
cd umbrawg-tools
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
bash scripts/check-packaging.sh
bash scripts/check-docs.sh                 # нужен собранный target/release/uwg
bash scripts/test-daemon-e2e.sh            # UAPI, автоскип без TUN

# daemon
cd umbrawg-rs
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
bash scripts/test-dataplane-e2e.sh         # два демона, автоскип без TUN

# kernel
cd umbrawg-linux-kernel-module/src
make LLVM=1
make module-debug LLVM=1
src/tests/netlink-parity.sh                # нужен загруженный модуль и root
sudo UWG=../../umbrawg-tools/target/release/uwg src/tests/fec-profile-change.sh
```

`cargo deny check` прогоняется во всех Rust-компонентах (в CI — отдельные
джобы). Убедись, что `master` чистый и все feature-ветки слиты.

## crates.io

Публикация нужна только для `netlink-packet-umbrawg` (зависимость tools) и,
при желании, для утилит:

1. `cargo publish -p netlink-packet-umbrawg` из `netlink-packet-umbrawg`.
2. Для публикации `uwg`/`uwg-quick` сначала опубликуй внутренние крейты
   `umbrawg-config` и `umbrawg-ctl` (версии `0.5.0`), затем `uwg` и
   `uwg-quick`. Зависимости уже содержат `version` + `path`.
3. Для `umbrawg-rs` публикация не планируется: демон распространяется
   пакетами и tarball'ами.

## Arch / AUR

PKGBUILD лежат в `contrib/arch/<pkgname>/` каждого компонента. Стабильные
PKGBUILD уже указывают на теги `0.5.0`:

- `netlink-packet-umbrawg/contrib/arch/rust-netlink-packet-umbrawg/` —
  `netlink-v0.5.0`;
- `umbrawg-tools/contrib/arch/umbrawg-tools/` — `tools-v0.5.0` +
  `netlink-v0.5.0`;
- `umbrawg-rs/contrib/arch/umbrawg-daemon/` — `rs-v0.5.0`;
- `umbrawg-linux-kernel-module/contrib/arch/umbrawg-dkms/` — `kernel-v0.5.0`.

Пока теги не запушены, `sha256sums` намеренно содержит заглушку
`TODO_UPDPKGSUMS_AFTER_FIRST_TAG` — выдуманный хэш хуже явной заглушки.

1. Дождись, что все четыре тега из раздела «Порядок тегов» запушены.
2. Для каждого стабильного PKGBUILD пересчитай суммы и `.SRCINFO`:

   ```sh
   cd contrib/arch/<pkgname>
   updpkgsums
   makepkg --printsrcinfo > .SRCINFO
   ```

3. Проверь, что в `source`/`.SRCINFO` нет заглушки и версия совпадает с
   тегом (`0.5.0`).
4. Скопируй `PKGBUILD`, `*.install` (если есть) и `.SRCINFO` в корень
   соответствующего AUR-репозитория и запушь:
   - `umbrawg-dkms`, `umbrawg-dkms-git`
   - `umbrawg-tools`, `umbrawg-tools-git`
   - `umbrawg-daemon`, `umbrawg-daemon-git`
   - `rust-netlink-packet-umbrawg`, `rust-netlink-packet-umbrawg-git`
5. `-git`-пакеты работают без тегов; стабильные — только после публикации
   тегов и `updpkgsums`.

## Debian / RPM

CI собирает пакеты на тег **своего** компонента:

- `kernel-v*` → `kernel-packaging.yml`: `.deb`, `.rpm`, Arch/DKMS;
- `netlink-v*` → `netlink-packaging.yml`: `.crate`, Arch;
- `tools-v*` → `tools-packaging.yml`: `.deb`, `.rpm`, Arch, tarball'ы;
- `rs-v*` → `rs-packaging.yml`: `.deb`, `.rpm`, Arch, tarball'ы.

Ручной прогон без публикации (релиз пропускается):

```sh
gh workflow run kernel-packaging.yml -f version=0.5.0
gh workflow run netlink-packaging.yml -f version=0.5.0
gh workflow run tools-packaging.yml -f version=0.5.0
gh workflow run rs-packaging.yml -f version=0.5.0
```

Локально:

```sh
scripts/package/build-deb.sh
scripts/package/build-rpm.sh
```

Для deb модуля версия берётся из `debian/changelog` и подставляется в
`dkms.conf`/`Makefile` в `debian/rules`; каталог один —
`/usr/src/umbrawg-0.5.0`.

## Проверка релиза

- `uwg --version`, `uwg-quick --help`, `uwg showconf` на живом демоне.
- Interop: демон ↔ модуль, демон ↔ `amneziawg-go`, с обфускацией и без.
- Замеры: `bench/bench.sh` с `REPEATS=3`, `CONNS_LIST="1 10"`,
  `OBF_LIST="0 1"`, MTU underlay 9000.
- `cargo deny check` во всех Rust-компонентах.
- Пакеты из CI скачаны и проверены (`dpkg-deb -c`, `rpm -qlp`,
  `bsdtar -tf`).

## Блокеры и открытые решения

- **Ядро**: +31.6…33.9% к amneziawg на TCP c=1 (final5); цель `3c c10`
  ≥~3090/2810 пока не достигнута (final5: 1800/1640). Следующий шаг —
  perf-гейт и RPS-проба по `docs/PEER-SHARDING.md`, затем S2-прототип.
- **Rust**: final5 — 1947/1719 на 1c c1, 2673/2591 на 3c c10; в multi-peer
  демон впервые лидер (5477/4971 против 5187/4443 у ядра и 4498/3499 у go)
  при меньших ретрансмитах. Узкое место — 1c и obf=1.
- **Параллельный RX** (`UMBRAWG_PARALLEL_RX=1`): на 3c c10 быстрее обычного
  rust на +8.0%/+9.8%, но на 1c и в multi-peer медленнее; остаётся opt-in и
  рекомендуется только для многоядерных хабов, не default-on.
- **MTU подложки**: `UMBRAWG_UNDERLAY_MTU` по умолчанию 1500; при S4=60 и
  TUN MTU 1420 датаграмма 1512 Б не влезает — включается IP-фрагментация
  (TCP падает в ~2.4 раза). Демон предупреждает; для таких профилей нужен
  TUN MTU ≤1380 или underlay 9000. Oversized-кадров GSO не даёт (≤1514).
- **Версия модуля**: каноническая `0.5.0`; `Makefile`/`dkms.conf`
  по умолчанию содержат `0.5.0` и переопределяются упаковкой.
- **AUR**: нужен аккаунт и SSH-ключ; публикация через `scripts/aur-publish.sh`
  после тегов и `updpkgsums`.
- **crates.io**: нужен токен; порядок публикации — netlink, затем внутренние
  крейты tools, затем `uwg`/`uwg-quick`.
