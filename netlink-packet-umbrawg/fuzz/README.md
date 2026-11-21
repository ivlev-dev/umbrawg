# Фаззинг

Установка (на сервере, при необходимости):

```sh
cargo install cargo-fuzz
```

Запуск (из `netlink-packet-umbrawg/fuzz`):

```sh
cargo fuzz run parse_message
cargo fuzz run parse_range
```

Ограничения: cargo-fuzz требует nightly toolchain (`rustup toolchain install nightly`).
```