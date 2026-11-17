# umbrawg-bench

Criterion-бенчмарки горячего пути UmbraWG.

## Запуск

На сервере сборки:

```sh
cd /root/umbrawg/rust
cargo bench -p umbrawg-bench --no-run
cargo bench -p umbrawg-bench
```

Короткий прогон:

```sh
cargo bench -p umbrawg-bench -- --sample-size 10 --measurement-time 1 --warm-up-time 1
```

Отдельная группа:

```sh
cargo bench -p umbrawg-bench -- aead_seal_in_place
```

## perf / flamegraph

```sh
perf record -g target/release/deps/hotpath-*
perf report
cargo install flamegraph
cargo flamegraph --bench hotpath -p umbrawg-bench
```

Отчёт criterion сохраняется в `target/criterion/`.
