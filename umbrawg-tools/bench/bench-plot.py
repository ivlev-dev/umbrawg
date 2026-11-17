#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import html
import math
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

IMPLEMENTATIONS: tuple[str, ...] = ("kernel-umbrawg", "kernel-amneziawg", "rust", "go")
KERNEL_REFERENCE = "kernel-amneziawg"
USERSPACE_REFERENCE = "go"
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
    extra: str
    run: str
    repeat: int
    cpu_hot: int | None = None
    cpu_total: float | None = None

    @property
    def extra_value(self) -> float | None:
        value = self.extra.strip()
        if not value or value == "-":
            return None
        try:
            return float(value)
        except ValueError:
            return None


@dataclass(frozen=True)
class CellKey:
    mode: str
    proto: str
    conns: int
    loss: float
    obf: str
    peers: int

    @property
    def chart_group(self) -> tuple[str, str, int, str]:
        return (self.proto, self.obf, self.conns, self.mode)

    @property
    def label(self) -> str:
        parts = [self.mode, self.proto, f"c={self.conns}"]
        parts.append(f"loss={self.loss:g}")
        parts.append(f"obf={self.obf}")
        parts.append(f"peers={self.peers}")
        return " ".join(parts)


@dataclass(frozen=True)
class Stat:
    median: float
    minimum: float
    maximum: float
    count: int
    median_extra: float | None = None
    median_hot: float | None = None
    median_total: float | None = None
    cpu_runs: int = 0

    @property
    def median_lost(self) -> float | None:
        return self.median_extra


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


def load_rows(path: Path | str) -> list[Row]:
    rows: list[Row] = []
    path = Path(path)
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            return rows
        for raw in reader:
            if raw is None:
                continue
            if None in (raw or {}):
                # stray columns without header; ignore
                pass
            mbit_text = _text(raw, "mbit", "")
            if not mbit_text or mbit_text.upper() == "FAIL":
                continue
            try:
                mbit = float(mbit_text)
            except ValueError:
                continue
            proto = _text(raw, "proto", "tcp")
            impl = _text(raw, "impl", "unknown")
            if not impl:
                continue
            loss = _float(raw, "loss", 0.0)
            try:
                conns = _int(raw, "conns", 1)
            except ValueError:
                conns = 1
            peers = _int(raw, "peers", 1)
            obf = _text(raw, "obf", "0")
            mode = _text(raw, "mode", "1c")
            extra = _text(raw, "extra", "")
            run = _text(raw, "run", "")
            repeat = _int(raw, "repeat", 0)
            cpu_hot = _opt_int(raw, "cpu_hot")
            cpu_total = _opt_float(raw, "cpu_total")
            rows.append(
                Row(
                    impl=impl,
                    mode=mode,
                    proto=proto,
                    conns=conns,
                    loss=loss,
                    obf=obf,
                    peers=peers,
                    mbit=mbit,
                    extra=extra,
                    run=run,
                    repeat=repeat,
                    cpu_hot=cpu_hot,
                    cpu_total=cpu_total,
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
    )


def aggregate(rows: Sequence[Row]) -> dict[tuple[str, CellKey], Stat]:
    buckets: dict[tuple[str, CellKey], list[Row]] = {}
    for row in rows:
        buckets.setdefault((row.impl, cell_key(row)), []).append(row)
    stats: dict[tuple[str, CellKey], Stat] = {}
    for key, items in buckets.items():
        values = [item.mbit for item in items]
        extra_values = [item.extra_value for item in items if item.extra_value is not None]
        hot_values = [item.cpu_hot for item in items if item.cpu_hot is not None]
        total_values = [item.cpu_total for item in items if item.cpu_total is not None]
        stats[key] = Stat(
            median=statistics.median(values),
            minimum=min(values),
            maximum=max(values),
            count=len(values),
            median_extra=statistics.median(extra_values) if extra_values else None,
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


def cell_sort_key(key: CellKey) -> tuple[int, str, int, str, int, float]:
    mode_rank = 0 if key.mode == "1c" else 1
    return (mode_rank, key.proto, key.conns, key.obf, key.peers, key.loss)


def group_rows(rows: Sequence[Row]) -> dict[tuple[str, str, int, str], list[Row]]:
    buckets: dict[tuple[str, str, int, str], list[Row]] = {}
    for row in rows:
        buckets.setdefault((row.proto, row.obf, row.conns, row.mode), []).append(row)
    return buckets


def group_cells(rows: Sequence[Row]) -> dict[CellKey, list[Row]]:
    buckets: dict[CellKey, list[Row]] = {}
    for row in rows:
        buckets.setdefault(cell_key(row), []).append(row)
    return buckets


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


def fmt_stat(stat: Stat | None) -> str:
    if stat is None:
        return "-"
    if stat.count <= 1:
        return f"{stat.median:.1f}"
    return f"{stat.median:.1f} [{stat.minimum:.1f}–{stat.maximum:.1f}]"


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


COLORS = {
    "kernel-umbrawg": "#2563eb",
    "kernel-amneziawg": "#64748b",
    "rust": "#ea580c",
    "go": "#16a34a",
}


def _color(impl: str) -> str:
    if impl in COLORS:
        return COLORS[impl]
    # stable-ish color
    palette = ["#7c3aed", "#0891b2", "#ca8a04", "#dc2626", "#4f46e5"]
    return palette[hash(impl) % len(palette)]


def _svg_chart(group: tuple[str, str, int, str], impls: list[str], medians: dict[str, float], extras: dict[str, float | None], warns: set[str]) -> str:
    proto, obf, conns, mode = group
    title = f"{proto.upper()} · obf={obf} · conns={conns} · mode={mode}"
    if not impls:
        return ""
    W = 420
    H = 260
    pad_left = 52
    pad_right = 16
    pad_top = 34
    pad_bottom = 58
    plot_w = W - pad_left - pad_right
    plot_h = H - pad_top - pad_bottom
    ymax = max(medians.values()) if medians else 1.0
    if ymax <= 0:
        ymax = 1.0
    ymax = ymax * 1.18
    n = len(impls)
    slot = plot_w / max(n, 1)
    bar_w = min(slot * 0.62, 60)
    parts: list[str] = []
    parts.append(f'<svg viewBox="0 0 {W} {H}" class="chart" role="img" aria-label="{_esc(title)}">')
    parts.append(f'<text x="{W/2:.1f}" y="20" text-anchor="middle" class="chart-title">{_esc(title)}</text>')
    # y axis ticks
    for i in range(5):
        frac = i / 4.0
        y = pad_top + plot_h * (1 - frac)
        val = ymax * frac
        parts.append(f'<line x1="{pad_left}" y1="{y:.1f}" x2="{W-pad_right}" y2="{y:.1f}" class="grid"/>')
        parts.append(f'<text x="{pad_left-6}" y="{y+4:.1f}" text-anchor="end" class="tick">{val:.0f}</text>')
    parts.append(f'<line x1="{pad_left}" y1="{pad_top}" x2="{pad_left}" y2="{pad_top+plot_h}" class="axis"/>')
    parts.append(f'<line x1="{pad_left}" y1="{pad_top+plot_h}" x2="{W-pad_right}" y2="{pad_top+plot_h}" class="axis"/>')
    for i, impl in enumerate(impls):
        med = medians.get(impl, 0.0)
        h = (med / ymax) * plot_h if ymax else 0.0
        cx = pad_left + slot * (i + 0.5)
        x = cx - bar_w / 2
        y = pad_top + plot_h - h
        color = _color(impl)
        warn = impl in warns
        stroke = ' stroke="#dc2626" stroke-width="2"' if warn else ""
        parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{h:.1f}" fill="{color}" rx="3"{stroke}/>')
        parts.append(f'<text x="{cx:.1f}" y="{y-4:.1f}" text-anchor="middle" class="val">{med:.1f}</text>')
        # x label (rotate-ish via short names)
        parts.append(f'<text x="{cx:.1f}" y="{pad_top+plot_h+16:.1f}" text-anchor="middle" class="xlabel">{_esc(impl)}</text>')
        extra = extras.get(impl)
        if extra is not None:
            parts.append(f'<text x="{cx:.1f}" y="{pad_top+plot_h+30:.1f}" text-anchor="middle" class="xsub">extra {extra:.2g}</text>')
    parts.append('</svg>')
    return "\n".join(parts)


def _has_cpu(rows: Sequence[Row]) -> bool:
    return any(r.cpu_hot is not None or r.cpu_total is not None for r in rows)


def _has_extra(rows: Sequence[Row]) -> bool:
    return any(r.extra_value is not None for r in rows)


def build_html(rows: Sequence[Row], title: str | None = None, source: Path | str | None = None) -> str:
    if title is None:
        title = "Отчёт стенда UmbraWG"
    stats = aggregate(rows)
    impls = impl_order(rows)
    has_cpu = _has_cpu(rows)
    has_extra = _has_extra(rows)

    # chart groups
    groups: dict[tuple[str, str, int, str], dict[str, list[Row]]] = {}
    for row in rows:
        g = (row.proto, row.obf, row.conns, row.mode)
        groups.setdefault(g, {}).setdefault(row.impl, []).append(row)

    chart_html: list[str] = []
    for group in sorted(groups, key=lambda g: (g[0], int(g[1]) if g[1].isdigit() else g[1], g[2], g[3])):
        impl_map = groups[group]
        group_impls = [impl for impl in impls if impl in impl_map]
        medians: dict[str, float] = {}
        extras: dict[str, float | None] = {}
        warns: set[str] = set()
        for impl in group_impls:
            items = impl_map[impl]
            vals = [r.mbit for r in items]
            medians[impl] = statistics.median(vals) if vals else 0.0
            evs = [r.extra_value for r in items if r.extra_value is not None]
            extras[impl] = statistics.median(evs) if evs else None
            # warn if udp and loss>1%
            if group[0] == "udp":
                if extras[impl] is not None and extras[impl] > 1.0:
                    warns.add(impl)
        chart_html.append('<div class="chart-card">')
        chart_html.append(_svg_chart(group, group_impls, medians, extras, warns))
        chart_html.append("</div>")

    # warnings
    warnings: list[str] = []
    # n=1 cells
    single = sorted({key.label for (_, key), stat in stats.items() if stat.count < 2})
    if single:
        warnings.append(f"без повторов (n=1, выводы ненадёжны): {len(single)} ячеек")
    # udp loss > 1%
    udp_lossy = sorted({
        f"{impl} {key.label}: {stat.median_extra:.2f}%"
        for (impl, key), stat in stats.items()
        if key.proto == "udp" and stat.median_extra is not None and stat.median_extra > 1.0
    })
    if udp_lossy:
        warnings.append(f"потери UDP > 1%: {len(udp_lossy)} ячеек")
    if not warnings:
        warnings.append("нет")

    # table rows
    table_rows: list[str] = []
    for (impl, key), stat in sorted(stats.items(), key=lambda item: (cell_sort_key(item[0][1]), item[0][0])):
        warn = key.proto == "udp" and stat.median_extra is not None and stat.median_extra > 1.0
        row_class = ' class="warn"' if warn else ""
        cells: list[str] = []
        cells.append(f"<td>{_esc(impl)}</td>")
        cells.append(f"<td>{_esc(key.label)}</td>")
        cells.append(f"<td>{stat.median:.1f}</td>")
        cells.append(f"<td>{stat.minimum:.1f}</td>")
        cells.append(f"<td>{stat.maximum:.1f}</td>")
        cells.append(f"<td>{stat.count}</td>")
        if has_extra:
            extra_text = "-" if stat.median_extra is None else f"{stat.median_extra:.2f}"
            cells.append(f"<td>{_esc(extra_text)}</td>")
        if has_cpu:
            hot_text = "-" if stat.median_hot is None else f"{stat.median_hot:g}"
            total_text = "-" if stat.median_total is None else f"{stat.median_total:.0f}%"
            verdict = cpu_verdict(stat.median_hot, stat.median_total)
            cells.append(f"<td>{_esc(hot_text)}</td>")
            cells.append(f"<td>{_esc(total_text)}</td>")
            cells.append(f"<td>{_esc(verdict)}</td>")
        table_rows.append(f"<tr{row_class}>{''.join(cells)}</tr>")

    # header
    header_cells = ["<th>Реализация</th>", "<th>Ячейка</th>", "<th>Медиана</th>", "<th>Min</th>", "<th>Max</th>", "<th>n</th>"]
    if has_extra:
        header_cells.append("<th>Потери (extra)</th>")
    if has_cpu:
        header_cells.append("<th>CPU hot</th>")
        header_cells.append("<th>CPU total</th>")
        header_cells.append("<th>Вердикт</th>")

    source_text = ""
    if source is not None:
        source_text = f"<p class=\"meta\">CSV: {_esc(source)}</p>"

    html_parts: list[str] = []
    html_parts.append("<!DOCTYPE html>")
    html_parts.append('<html lang="ru"><head><meta charset="utf-8">')
    html_parts.append(f"<title>{_esc(title)}</title>")
    html_parts.append("<style>")
    html_parts.append("""
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:24px;color:#1f2937;background:#f9fafb}
h1{margin:0 0 8px} h2{margin:24px 0 8px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}
.meta{color:#6b7280;font-size:13px}
.summary{display:flex;gap:16px;flex-wrap:wrap;margin:12px 0}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;min-width:140px}
.card .label{font-size:12px;color:#6b7280} .card .value{font-size:20px;font-weight:600}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:16px}
.chart-card{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:8px}
.chart-title{font-size:13px;font-weight:600;fill:#374151}
.grid{stroke:#e5e7eb;stroke-width:1} .axis{stroke:#9ca3af;stroke-width:1.5}
.tick{font-size:10px;fill:#6b7280} .val{font-size:11px;font-weight:600;fill:#111827}
.xlabel{font-size:10px;fill:#374151} .xsub{font-size:9px;fill:#6b7280}
table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden}
th,td{padding:8px 10px;border-bottom:1px solid #e5e7eb;font-size:13px;text-align:left}
th{background:#f3f4f6;font-weight:600} tr.warn{background:#fef2f2}
tr.warn td{color:#991b1b}
.warnbox{background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px;margin:12px 0}
.warnbox ul{margin:6px 0 0;padding-left:20px}
""")
    html_parts.append("</style></head><body>")
    html_parts.append(f"<h1>{_esc(title)}</h1>")
    html_parts.append(source_text)
    html_parts.append('<div class="summary">')
    html_parts.append(f'<div class="card"><div class="label">Строк</div><div class="value">{len(rows)}</div></div>')
    html_parts.append(f'<div class="card"><div class="label">Реализаций</div><div class="value">{len(impls)}</div></div>')
    html_parts.append(f'<div class="card"><div class="label">Ячеек</div><div class="value">{len(stats)}</div></div>')
    html_parts.append(f'<div class="card"><div class="label">Макс. повторов</div><div class="value">{max((s.count for s in stats.values()), default=0)}</div></div>')
    html_parts.append("</div>")
    html_parts.append("<h2>Графики</h2>")
    html_parts.append('<div class="charts">')
    html_parts.append("\n".join(chart_html) if chart_html else "<p>Нет данных для графиков.</p>")
    html_parts.append("</div>")
    html_parts.append("<h2>Таблица: реализация × ячейка</h2>")
    html_parts.append("<table><thead><tr>" + "".join(header_cells) + "</tr></thead><tbody>")
    html_parts.append("\n".join(table_rows) if table_rows else "<tr><td colspan=\"10\">Нет данных.</td></tr>")
    html_parts.append("</tbody></table>")
    html_parts.append("<h2>Предупреждения</h2>")
    html_parts.append('<div class="warnbox"><ul>' + "".join(f"<li>{w}</li>" for w in warnings) + "</ul></div>")
    # detailed udp loss list
    if udp_lossy:
        html_parts.append("<ul>" + "".join(f"<li>{_esc(x)}</li>" for x in udp_lossy) + "</ul>")
    html_parts.append("</body></html>")
    return "\n".join(html_parts)


def build_report(source, rows=None, title=None) -> str:
    if rows is None:
        # allow build_report(rows, title=...) form
        if isinstance(source, (list, tuple)):
            rows = source
            source = None
        else:
            rows = []
    return build_html(rows, title=title, source=source)


# aliases
build_html_report = build_report
render = build_report
render_html = build_html
to_html = build_html
generate = build_report
generate_html = build_html


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Визуализация CSV стенда UmbraWG в HTML")
    parser.add_argument("csv", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=None)
    parser.add_argument("--title", type=str, default=None)
    args = parser.parse_args(argv)

    if not args.csv.exists():
        print(f"нет файла: {args.csv}", file=sys.stderr)
        return 1
    rows = load_rows(args.csv)
    if not rows:
        print("нет данных", file=sys.stderr)
        return 1
    html_text = build_report(args.csv, rows, args.title)
    if args.output is not None:
        args.output.write_text(html_text, encoding="utf-8")
    else:
        print(html_text)
    return 0


# compatibility aliases
parse_rows = load_rows
read_rows = load_rows
aggregate_rows = aggregate
group_by = group_rows
group = group_rows
group_data = group_rows
group_charts = group_rows
group_chart = group_rows
build = build_report
render_report = build_report


if __name__ == "__main__":
    raise SystemExit(main())
