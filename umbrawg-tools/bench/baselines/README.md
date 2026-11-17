# Эталонные матрицы (baselines)

Каталог хранит эталонные прогоны стенда для будущих сравнений через
`bench/bench-compare.py`. Данные привязаны к конкретному железу и стенду:
абсолютные числа не переносимы на другие машины, сравнивать можно только
относительные дельты на том же стенде.

## final5-20261117

Файл: `final5-20261117.csv` (агрегат — `final5-20261117.csv.agg.csv`).
Единый финальный прогон после всех фиксов Rust (per-byte Poly1305, буферы
сокетов, флуд-детектор, GSO/MTU): 240 ячеек, 0 падений, REPEATS=3. Источник —
`/root/umbrawg/bench/results/final5-20261117.csv` и отчёт `docs/RESULTS.md`.

### Условия замеров

- Сервер: 6 vCPU, ядро `7.3.4-1-cachyos-eevdf-lto`, единственный пользователь
  (хост гипервизора занят — дрейф до ~15% на c=10).
- Стенд: `bench.sh` с `IDLE_GUARD`, `REPEATS=3`, `DURATION=5`,
  `UNDERLAY_MTU=9000`, `TUN_MTU=1420`.
- iperf3 запускается на отдельном ядре (`IPERF_CPU`, по умолчанию 3);
  результат ячейки — медиана 3 повторов, Мбит/с по `sum_received`.

### Версии и коммиты

- модуль ядра `umbrawg`: `/root/umbrawg/module-final2` @ `050c12d`
  (`= module-master`, `make LLVM=1`),
  md5 `a6930724083a9d32a41cc701f2af188a` (совпал с final4);
- Rust-демон: `/root/umbrawg/rust` @ `c340382` (merge `feature/gso-mtu`),
  `cargo build --release`, sha256 `efab7d28…`;
- tools: `/root/umbrawg/tools` @ `2b1077d`, `uwg` v0.2.0,
  sha256 `ae83c920…`;
- netlink-крейт: `netlink-packet-umbrawg` 0.3.0 (`Cargo.lock` tools).

### Матрица

5 реализаций (`kernel-umbrawg`, `kernel-amneziawg`, `rust`, `rust-par`, `go`)
× режим ядер `1c`/`3c` × обфускация `obf 0/1` × протокол `tcp`/`udp` ×
число соединений `conns 1/10` (все при `loss=0`, `peers=1`).

### Сравнение

```bash
python3 bench/bench-compare.py bench/baselines/final5-20261117.csv <new.csv> --threshold 10 --md report.md
python3 bench/bench-compare.py bench/baselines/final4-20261117.csv bench/baselines/final5-20261117.csv --threshold 10 --md final4-vs-final5.md
```

Порог регрессии по умолчанию — 10%; для c=10 на этом стенде шум доходит до
~15% (см. `docs/RESULTS.md`, раздел «Ограничения»).

### Ключевые ячейки

- `1c`, `c=1`, `obf=0` и `obf=1` — базовый случай userspace/kernel;
- `3c`, `c=10`, `obf=0` и `obf=1` — пиковая пропускная способность:
  `rust` 2673/2591 против `kernel-umbrawg` 1800/1640 Мбит/с.

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
