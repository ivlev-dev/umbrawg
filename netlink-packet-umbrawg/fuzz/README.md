# Фаззинг

Установка (на сервере, при необходимости):

```sh
cargo install cargo-fuzz
```

Запуск:

```sh
cd /root/umbrawg/netlink/fuzz
cargo fuzz run parse_message
cargo fuzz run parse_range
```

Ограничения: cargo-fuzz требует nightly toolchain (`rustup toolchain install nightly`).
```