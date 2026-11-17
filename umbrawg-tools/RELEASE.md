# Выпуск UmbraWG

Единый чек-лист для четырёх репозиториев. Часть шагов зависит от тегов и
публикации; до первого релиза проверь раздел «Блокеры».

## Компоненты и версии

| Репозиторий | Пакет(ы) | Версия | Тег |
|---|---|---|---|
| `netlink-packet-umbrawg` | крейт, `rust-netlink-packet-umbrawg` | `0.3.0` | `v0.3.0` |
| `umbrawg-tools` | `uwg`, `uwg-quick`, `umbrawg-tools` | `0.2.0` | `v0.2.0` |
| `umbrawg-rs` | демон `umbrawg`, `umbrawg-daemon` | `0.1.0` | `v0.1.0` |
| `umbrawg-linux-kernel-module` | DKMS-модуль | `3.1.20261113-02` | `v3.1.20261113-02` |

Каноническая строка версии модуля — `3.1.20261113-02`. Пакетные менеджеры
нормализуют её: Arch — `3.1.20261113_02`, RPM — `3.1.20261113_02`,
Debian — upstream `3.1.20261113`, revision `02` (полная версия пакета
`3.1.20261113-02`). `modinfo` показывает `3.1.20261113-02`.

## Порядок тегов

Теги ставятся и пушатся строго по порядку:

1. `netlink-packet-umbrawg` — `v0.3.0`.
2. `umbrawg-tools` — `v0.2.0` (зависит от netlink 0.3.0 и его lock).
3. `umbrawg-rs` — `v0.1.0`.
4. `umbrawg-linux-kernel-module` — `v3.1.20261113-02`.

Причина: `umbrawg-tools/Cargo.lock` собран против `netlink-packet-umbrawg`
0.3.0. Если сначала выпустить tools, CI возьмёт netlink из `main` со старой
версией и `cargo fetch --locked` упадёт.

## Перед тегом (в каждом репозитории)

```sh
cargo test --workspace            # netlink: cargo test --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo +nightly fmt --all -- --check
cargo deny check
```

Для tools дополнительно:

```sh
bash scripts/check-packaging.sh
bash scripts/check-docs.sh        # нужен собранный target/release/uwg
bash scripts/test-daemon-e2e.sh   # UAPI, автоскип без TUN
```

Для демона:

```sh
bash scripts/test-dataplane-e2e.sh  # два демона, автоскип без TUN
```

Для модуля:

```sh
cd src && make LLVM=1
make module-debug LLVM=1
src/tests/netlink-parity.sh
```

Убедись, что `master`/`main` чистые и все feature-ветки слиты.

## crates.io

Публикация нужна только для `netlink-packet-umbrawg` (зависимость tools) и,
при желании, для утилит:

1. `cargo publish -p netlink-packet-umbrawg` из `netlink-packet-umbrawg`.
2. Для публикации `uwg`/`uwg-quick` сначала опубликуй внутренние крейты
   `umbrawg-config` и `umbrawg-ctl` (версии `0.2.0`), затем `uwg` и
   `uwg-quick`. Зависимости уже содержат `version` + `path`.
3. Для `umbrawg-rs` публикация не планируется: демон распространяется
   пакетами и tarball'ами.

## Arch / AUR

PKGBUILD лежат в `contrib/arch/<pkgname>/` каждого репозитория.

1. После тегов обнови `sha256sums` в стабильных PKGBUILD через `updpkgsums`
   (сейчас там заглушки `TODO_UPDPKGSUMS_AFTER_FIRST_TAG`).
2. Перегенерируй `.SRCINFO`: `makepkg --printsrcinfo > .SRCINFO`.
3. Скопируй `PKGBUILD`, `*.install`, `.SRCINFO` в корень соответствующего
   AUR-репозитория и запушь:
   - `umbrawg-dkms`, `umbrawg-dkms-git`
   - `umbrawg-tools`, `umbrawg-tools-git`
   - `umbrawg-daemon`, `umbrawg-daemon-git`
   - `rust-netlink-packet-umbrawg`, `rust-netlink-packet-umbrawg-git`
4. `-git`-пакеты работают без тегов; стабильные — только после публикации
   тегов и `updpkgsums`.

## Debian / RPM

CI собирает пакеты на тег `v*`:

- tools: `.deb`, `.rpm`, Arch;
- module: `.deb`, `.rpm`, Arch;
- rust: Arch;
- netlink: Arch + `cargo package`/`--dry-run`.

Локально:

```sh
scripts/package/build-deb.sh
scripts/package/build-rpm.sh
```

Для deb модуля версия берётся из `debian/changelog` и подставляется в
`dkms.conf`/`Makefile` в `debian/rules`; каталог один —
`/usr/src/umbrawg-3.1.20261113-02`.

## Проверка релиза

- `uwg --version`, `uwg-quick --help`, `uwg showconf` на живом демоне.
- Interop: демон ↔ модуль, демон ↔ `amneziawg-go`, с обфускацией и без.
- Замеры: `bench/bench.sh` с `REPEATS=3`, `CONNS_LIST="1 10"`,
  `OBF_LIST="0 1"`, MTU underlay 9000.
- `cargo deny check` во всех Rust-репозиториях.
- `pkgs` из CI скачаны и проверены (`dpkg-deb -c`, `rpm -qlp`,
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
- **Версия модуля**: каноническая `3.1.20261113-02`; `Makefile`/`dkms.conf`
  по умолчанию содержат `1.0.0` и переопределяются упаковкой. Реши, нужно ли
  синхронизировать исходники.
- **AUR**: нужен аккаунт и SSH-ключ; публикация через `scripts/aur-publish.sh`
  после тегов и `updpkgsums`.
- **crates.io**: нужен токен; порядок публикации — netlink, затем внутренние
  крейты tools, затем `uwg`/`uwg-quick`.
