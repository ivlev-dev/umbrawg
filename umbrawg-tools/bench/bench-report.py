#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

IMPLEMENTATIONS: tuple[str, ...] = ("kernel-umbrawg", "kernel-amneziawg", "rust", "go")
KERNEL_REFERENCE = "kernel-amneziawg"
USERSPACE_REFERENCE = "go"
STREAM_SINGLE = "single"
STREAM_MULTI = "multi"
CPU_SINGLE_TOTAL_PCT = 95.0
CPU_PARALLEL_TOTAL_PCT = 130.0
CPU_LOW_TOTAL_PCT = 50.0


@dataclass(frozen=True)
class Row:
    impl: str
    mode: str
    proto: str
    conns: int
    loss: float
    obf: str
    peers: int
    mbit: float
    rate: str
    repeat: int
    lost: float | None
    frag: int
    cpu_hot: int | None = None
    cpu_total: float | None = None


@dataclass(frozen=True)
class CellKey:
    mode: str
    proto: str
    conns: int
    loss: float
    obf: str
    peers: int
    rate: str

    @property
    def streams(self) -> str:
        return STREAM_SINGLE if self.conns <= 1 else STREAM_MULTI


@dataclass(frozen=True)
class Stat:
    median: float
    minimum: float
    maximum: float
    count: int
    median_lost: float | None
    median_hot: float | None = None
    median_total: float | None = None
    cpu_runs: int = 0


def _text(raw: dict[str, str], key: str, default: str) -> str:
    value = raw.get(key)
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def _int(raw: dict[str, str], key: str, default: int) -> int:
    value = _text(raw, key, "")
    if not value or value == "-":
        return default
    try:
        return int(float(value))
    except ValueError:
        return default


def _float(raw: dict[str, str], key: str, default: float) -> float:
    value = _text(raw, key, "")
    if not value or value == "-":
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _opt_float(raw: dict[str, str], key: str) -> float | None:
    value = _text(raw, key, "")
    if not value or value == "-":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _opt_int(raw: dict[str, str], key: str) -> int | None:
    value = _text(raw, key, "")
    if not value or value == "-":
        return None
    try:
        return int(float(value))
    except ValueError:
        return None


def load_rows(path: Path) -> list[Row]:
    rows: list[Row] = []
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for raw in reader:
            mbit_text = _text(raw, "mbit", "")
            if not mbit_text or mbit_text.upper() == "FAIL":
                continue
            try:
                mbit = float(mbit_text)
            except ValueError:
                continue
            proto = _text(raw, "proto", "tcp")
            rate = _text(raw, "udp_rate", "")
            if proto == "tcp":
                rate = "-"
            elif not rate:
                rate = "legacy"
            lost = _opt_float(raw, "lost_percent")
            if lost is None and proto == "udp":
                lost = _opt_float(raw, "extra")
            rows.append(
                Row(
                    impl=_text(raw, "impl", "unknown"),
                    mode=_text(raw, "mode", "1c"),
                    proto=proto,
                    conns=_int(raw, "conns", 1),
                    loss=_float(raw, "loss", 0.0),
                    obf=_text(raw, "obf", "0"),
                    peers=_int(raw, "peers", 1),
                    mbit=mbit,
                    rate=rate,
                    repeat=_int(raw, "repeat", 0),
                    lost=lost,
                    frag=_int(raw, "frag", 0),
                    cpu_hot=_opt_int(raw, "cpu_hot"),
                    cpu_total=_opt_float(raw, "cpu_total"),
                )
            )
    return rows


def cell_key(row: Row) -> CellKey:
    return CellKey(
        mode=row.mode,
        proto=row.proto,
        conns=row.conns,
        loss=row.loss,
        obf=row.obf,
        peers=row.peers,
        rate=row.rate,
    )


def aggregate(rows: Sequence[Row]) -> dict[tuple[str, CellKey], Stat]:
    buckets: dict[tuple[str, CellKey], list[Row]] = {}
    for row in rows:
        buckets.setdefault((row.impl, cell_key(row)), []).append(row)
    stats: dict[tuple[str, CellKey], Stat] = {}
    for key, items in buckets.items():
        values = [item.mbit for item in items]
        lost_values = [item.lost for item in items if item.lost is not None]
        hot_values = [item.cpu_hot for item in items if item.cpu_hot is not None]
        total_values = [item.cpu_total for item in items if item.cpu_total is not None]
        stats[key] = Stat(
            median=statistics.median(values),
            minimum=min(values),
            maximum=max(values),
            count=len(values),
            median_lost=statistics.median(lost_values) if lost_values else None,
            median_hot=float(statistics.median(hot_values)) if hot_values else None,
            median_total=float(statistics.median(total_values)) if total_values else None,
            cpu_runs=len(hot_values),
        )
    return stats


def impl_order(rows: Sequence[Row]) -> list[str]:
    present = {row.impl for row in rows}
    ordered = [impl for impl in IMPLEMENTATIONS if impl in present]
    ordered.extend(sorted(present - set(ordered)))
    return ordered


def cell_sort_key(key: CellKey) -> tuple[int, int, str, int, str, int, str, float]:
    stream_rank = 0 if key.streams == STREAM_SINGLE else 1
    mode_rank = 0 if key.mode == "1c" else 1
    return (stream_rank, mode_rank, key.proto, key.conns, key.obf, key.peers, key.rate, key.loss)


def fmt_stat(stat: Stat | None) -> str:
    if stat is None:
        return "-"
    if stat.count <= 1:
        return f"{stat.median:.1f}"
    return f"{stat.median:.1f} [{stat.minimum:.1f}–{stat.maximum:.1f}]"


def fmt_delta(value: float, reference: float) -> str:
    if reference == 0:
        return "-"
    delta = (value - reference) / reference * 100.0
    return f"{delta:+.1f}%"


def fmt_hot(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:g}"


def fmt_pct(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.0f}%"


def cpu_verdict(hot: float | None, total: float | None) -> str:
    if hot is None or total is None:
        return "-"
    if hot == 1 and total >= CPU_SINGLE_TOTAL_PCT:
        return "single-core bound"
    if hot >= 2 or total >= CPU_PARALLEL_TOTAL_PCT:
        return "параллельно"
    if total < CPU_LOW_TOTAL_PCT:
        return "не CPU-bound"
    return "промежуточно"


def cpu_sections(stats: dict[tuple[str, CellKey], Stat]) -> list[str]:
    lines: list[str] = [
        "`hot` — число ядер с загрузкой ≥80% (порог стенда), `busy%` — суммарная "
        "загрузка машины. Вердикт: `single-core bound` — одно горячее ядро и "
        "суммарно ≥95%; `параллельно` — ≥2 горячих ядер или суммарно ≥130%; "
        "`не CPU-bound` — суммарно <50%.",
        "",
    ]
    any_data = False
    for stream, title in (
        (STREAM_SINGLE, "1 поток (iperf3 -P 1)"),
        (STREAM_MULTI, "Много потоков (iperf3 -P > 1)"),
    ):
        items = sorted(
            (
                (impl, key, stat)
                for (impl, key), stat in stats.items()
                if key.streams == stream and stat.median_total is not None
            ),
            key=lambda item: (cell_sort_key(item[1]), item[0]),
        )
        if not items:
            continue
        any_data = True
        lines.append(f"### {title}")
        lines.append("")
        lines.append("| mode | proto | conns | obf | peers | impl | hot | busy% | вердикт |")
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for impl, key, stat in items:
            lines.append(
                "| "
                + " | ".join(
                    [
                        key.mode,
                        key.proto,
                        str(key.conns),
                        key.obf,
                        str(key.peers),
                        impl,
                        fmt_hot(stat.median_hot),
                        fmt_pct(stat.median_total),
                        cpu_verdict(stat.median_hot, stat.median_total),
                    ]
                )
                + " |"
            )
        lines.append("")
    if not any_data:
        lines.extend(
            ["Нет данных CPU: CSV без колонок `cpu_hot`/`cpu_total` (старый формат).", ""]
        )
    return lines


def cell_label(key: CellKey) -> str:
    parts = [key.mode, key.proto, f"c={key.conns}"]
    if key.proto == "udp":
        parts.append(f"rate={key.rate}")
    parts.append(f"loss={key.loss:g}")
    parts.append(f"obf={key.obf}")
    parts.append(f"peers={key.peers}")
    return " ".join(parts)


def table_header(impls: Sequence[str]) -> list[str]:
    columns = ["mode", "proto", "conns", "loss", "obf", "peers", "udp_rate", *impls]
    return [
        "| " + " | ".join(columns) + " |",
        "|" + "---|" * len(columns),
    ]


def stream_sections(stats: dict[tuple[str, CellKey], Stat], impls: Sequence[str]) -> list[str]:
    lines: list[str] = []
    for stream, title in (
        (STREAM_SINGLE, "1 поток (iperf3 -P 1)"),
        (STREAM_MULTI, "Много потоков (iperf3 -P > 1)"),
    ):
        keys = sorted({key for (_, key) in stats if key.streams == stream}, key=cell_sort_key)
        if not keys:
            continue
        lines.append(f"### {title}")
        lines.append("")
        lines.extend(table_header(impls))
        for key in keys:
            cells: list[str] = []
            for impl in impls:
                stat = stats.get((impl, key))
                text = fmt_stat(stat)
                if stat is not None and stat.median_lost is not None:
                    text = f"{text} (loss {stat.median_lost:.2f}%)"
                cells.append(text)
            prefix = [
                key.mode,
                key.proto,
                str(key.conns),
                f"{key.loss:g}",
                key.obf,
                str(key.peers),
                key.rate,
            ]
            lines.append("| " + " | ".join([*prefix, *cells]) + " |")
        lines.append("")
    return lines


def family_reference(impl: str, present: set[str]) -> str | None:
    if impl.startswith("kernel-"):
        reference = KERNEL_REFERENCE
    else:
        reference = USERSPACE_REFERENCE
    if reference == impl or reference not in present:
        return None
    return reference


def comparison_section(
    stats: dict[tuple[str, CellKey], Stat],
    forced: str | None,
) -> list[str]:
    lines: list[str] = [
        "| ячейка | база | реализация | база Мбит/с | реализация Мбит/с | Δ |",
        "|---|---|---|---|---|---|",
    ]
    empty = True
    keys = sorted({key for (_, key) in stats}, key=cell_sort_key)
    for key in keys:
        present = {impl for (impl, cell) in stats if cell == key}
        for impl in sorted(present):
            if forced is not None:
                reference = forced if forced in present and forced != impl else None
            else:
                reference = family_reference(impl, present)
            if reference is None:
                continue
            base = stats[(reference, key)]
            stat = stats[(impl, key)]
            lines.append(
                "| "
                + " | ".join(
                    [
                        cell_label(key),
                        reference,
                        impl,
                        f"{base.median:.1f}",
                        f"{stat.median:.1f}",
                        fmt_delta(stat.median, base.median),
                    ]
                )
                + " |"
            )
            empty = False
    if empty:
        lines.append("| - | - | - | - | - | - |")
    lines.append("")
    return lines


def stream_summary(stats: dict[tuple[str, CellKey], Stat], impls: Sequence[str]) -> list[str]:
    lines: list[str] = [
        "| impl | proto | потоки | медиана медиан Мбит/с | ячеек |",
        "|---|---|---|---|---|",
    ]
    for impl in impls:
        for proto in ("tcp", "udp"):
            for stream, label in ((STREAM_SINGLE, "1"), (STREAM_MULTI, "много")):
                values = [
                    stat.median
                    for (cell_impl, key), stat in stats.items()
                    if cell_impl == impl and key.proto == proto and key.streams == stream
                ]
                if not values:
                    continue
                lines.append(
                    f"| {impl} | {proto} | {label} | {statistics.median(values):.1f} | {len(values)} |"
                )
    lines.append("")
    return lines


def warning_section(rows: Sequence[Row], stats: dict[tuple[str, CellKey], Stat]) -> list[str]:
    lines: list[str] = []
    single = sorted(
        {cell_label(key) for (_, key), stat in stats.items() if stat.count < 2},
    )
    if single:
        lines.append(
            f"- без повторов (n=1, выводы ненадёжны): {len(single)} ячеек, например {single[0]}"
        )
    fragmented = sorted({f"{row.impl} {cell_label(cell_key(row))}" for row in rows if row.frag > 0})
    if fragmented:
        lines.append(f"- фрагментация на пути: {len(fragmented)} прогонов, например {fragmented[0]}")
    overloaded = sorted(
        {
            f"{row.impl} {cell_label(cell_key(row))} loss={row.lost:.1f}%"
            for row in rows
            if row.lost is not None and row.lost >= 20.0
        }
    )
    if overloaded:
        lines.append(
            f"- потеряно ≥20% (goodput при перегрузе, не пропускная способность): {len(overloaded)} прогонов, например {overloaded[0]}"
        )
    if not lines:
        lines.append("- нет")
    lines.append("")
    return lines


def write_agg(path: Path, stats: dict[tuple[str, CellKey], Stat]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "impl",
                "mode",
                "proto",
                "conns",
                "loss",
                "obf",
                "peers",
                "udp_rate",
                "median_mbit",
                "min_mbit",
                "max_mbit",
                "runs",
                "median_lost_percent",
                "cpu_hot_median",
                "cpu_total_median",
                "cpu_verdict",
            ]
        )
        for (impl, key), stat in sorted(stats.items(), key=lambda item: (item[0][0], cell_sort_key(item[0][1]))):
            writer.writerow(
                [
                    impl,
                    key.mode,
                    key.proto,
                    key.conns,
                    f"{key.loss:g}",
                    key.obf,
                    key.peers,
                    key.rate,
                    f"{stat.median:.1f}",
                    f"{stat.minimum:.1f}",
                    f"{stat.maximum:.1f}",
                    stat.count,
                    "" if stat.median_lost is None else f"{stat.median_lost:.3f}",
                    "" if stat.median_hot is None else f"{stat.median_hot:g}",
                    "" if stat.median_total is None else f"{stat.median_total:.0f}",
                    cpu_verdict(stat.median_hot, stat.median_total),
                ]
            )


def build_report(path: Path, rows: Sequence[Row], forced: str | None) -> str:
    stats = aggregate(rows)
    impls = impl_order(rows)
    lines: list[str] = [
        "# Отчёт стенда UmbraWG",
        "",
        f"- CSV: `{path}`",
        f"- строк с результатами: {len(rows)}",
        f"- реализаций: {len(impls)} ({', '.join(impls) if impls else '-'})",
        f"- повторов на ячейку: {max((stat.count for stat in stats.values()), default=0)}",
        "",
        "Формат ячейки: `медиана [min–max]`, Мбит/с по `sum_received`.",
        "",
        "## Ячейки",
        "",
    ]
    if not rows:
        lines.extend(["Нет данных.", ""])
    else:
        lines.extend(stream_sections(stats, impls))
        lines.extend(["## Загрузка CPU", ""])
        lines.extend(cpu_sections(stats))
        lines.extend(["## Сравнение реализаций", ""])
        lines.extend(comparison_section(stats, forced))
        lines.extend(["## Агрегат по типу потока", ""])
        lines.extend(stream_summary(stats, impls))
        lines.extend(["## Предупреждения", ""])
        lines.extend(warning_section(rows, stats))
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Агрегация CSV стенда UmbraWG в Markdown")
    parser.add_argument("csv", type=Path)
    parser.add_argument("--md", type=Path, default=None)
    parser.add_argument("--agg", type=Path, default=None)
    parser.add_argument("--ref", type=str, default=None)
    args = parser.parse_args(argv)

    if not args.csv.exists():
        print(f"нет файла: {args.csv}", file=sys.stderr)
        return 1
    rows = load_rows(args.csv)
    report = build_report(args.csv, rows, args.ref)
    if args.md is not None:
        args.md.write_text(report, encoding="utf-8")
    else:
        print(report)
    if args.agg is not None:
        write_agg(args.agg, aggregate(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
