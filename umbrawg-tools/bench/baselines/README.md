# Эталонные матрицы (baselines)

Каталог хранит эталонные прогоны стенда для будущих сравнений через
`bench/bench-compare.py`. Данные привязаны к конкретному железу и стенду:
абсолютные числа не переносимы на другие машины, сравнивать можно только
относительные дельты на том же стенде.

## final4-20261117

Файл: `final4-20261117.csv` (агрегат — `final4-20261117.csv.agg.csv`).
Единый финальный прогон после GSO-фикса `obf=1`: 240 ячеек, 0 падений,
REPEATS=3. Источник — `/root/umbrawg/bench/results/final4-20261117.csv`
и отчёт `docs/RESULTS.md`.

### Условия замеров

- Сервер: 6 vCPU, ядро `7.3.4-1-cachyos-eevdf-lto`, единственный пользователь.
- Стенд: `bench.sh` с `IDLE_GUARD`, `REPEATS=3`, `DURATION=5`,
  `UNDERLAY_MTU=9000`, `TUN_MTU=1420`.
- iperf3 запускается на отдельном ядре (`IPERF_CPU`, по умолчанию 3);
  результат ячейки — медиана 3 повторов, Мбит/с по `sum_received`.

### Версии и коммиты

- модуль ядра `umbrawg`: `/root/umbrawg/module-final2` @ `58b291b`
  (`make LLVM=1`), md5 `a6930724083a9d32a41cc701f2af188a`;
- Rust-демон: `/root/umbrawg/rust` @ `53bc4b6`
  (`cargo build --release -p umbrawg`);
- tools: `/root/umbrawg/tools` @ `3cda779`, `uwg` v0.2.0;
- netlink-крейт: `netlink-packet-umbrawg` 0.3.0 (`Cargo.lock` tools).

### Матрица

5 реализаций (`kernel-umbrawg`, `kernel-amneziawg`, `rust`, `rust-par`, `go`)
× режим ядер `1c`/`3c` × обфускация `obf 0/1` × протокол `tcp`/`udp` ×
число соединений `conns 1/10` (все при `loss=0`, `peers=1`).

### Сравнение

```bash
python3 bench/bench-compare.py bench/baselines/final4-20261117.csv <new.csv> --threshold 10 --md report.md
```

Порог регрессии по умолчанию — 10%. Данные привязаны к железу и стенду,
абсолютные числа не переносимы; сравнивайте дельты на том же стенде.

### Ключевые ячейки

- `1c`, `c=1`, `obf=0` и `obf=1` (одно ядро, одно соединение — базовый
  случай userspace/kernel);
- `3c`, `c=10`, `obf=0` и `obf=1` (много ядер и соединений — пиковая
  пропускная способность).
