#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

LOSS_REGRESSION_THRESHOLD = 1.0


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
    loss_value: float | None = None

    @property
    def cell_key_tuple(self) -> tuple[str, str, str, int, float, str, int]:
        return (self.impl, self.mode, self.proto, self.conns, self.loss, self.obf, self.peers)


@dataclass(frozen=True)
class CellKey:
    impl: str
    mode: str
    proto: str
    conns: int
    loss: float
    obf: str
    peers: int

    def as_tuple(self) -> tuple[str, str, str, int, float, str, int]:
        return (self.impl, self.mode, self.proto, self.conns, self.loss, self.obf, self.peers)

    def label(self) -> str:
        parts = [self.impl, self.mode, self.proto, f"c={self.conns}"]
        parts.append(f"loss={self.loss:g}")
        parts.append(f"obf={self.obf}")
        parts.append(f"peers={self.peers}")
        return " ".join(parts)


@dataclass
class Stat:
    median: float
    minimum: float
    maximum: float
    count: int
    median_loss: float | None = None

    @property
    def median_mbit(self) -> float:
        return self.median

    @property
    def median_lost(self) -> float | None:
        return self.median_loss


@dataclass
class Comparison:
    key: CellKey
    baseline: Stat | None
    candidate: Stat | None
    delta_percent: float | None
    status: str

    @property
    def regression(self) -> bool:
        return self.status == "REGRESSION"

    @property
    def better(self) -> bool:
        return self.status == "BETTER"


@dataclass
class CompareResult:
    comparisons: list[Comparison]
    threshold: float
    has_regression: bool


def _text(raw: Mapping[str, str], key: str, default: str = "") -> str:
    value = raw.get(key)
    if value is None:
        return default
    value = str(value).strip()
    return value if value else default


def _int(raw: Mapping[str, str], key: str, default: int = 0) -> int:
    value = _text(raw, key, "")
    if not value or value == "-":
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _float(raw: Mapping[str, str], key: str, default: float = 0.0) -> float:
    value = _text(raw, key, "")
    if not value or value == "-":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _opt_float(raw: Any, key: str | None = None) -> float | None:
    if key is None:
        value = raw
    elif isinstance(raw, Mapping):
        value = raw.get(key)
    else:
        value = raw
    if value is None:
        return None
    text = str(value).strip()
    if not text or text == "-":
        return None
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def load_rows(path: Any) -> list[Row]:
    rows: list[Row] = []
    p = Path(path)
    if not p.exists():
        return rows
    with p.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            return rows
        for raw in reader:
            if not raw:
                continue
            if None in raw:
                # ignore stray extra columns
                pass
            mbit_text = _text(raw, "mbit", "")
            if not mbit_text or mbit_text.upper() == "FAIL":
                continue
            try:
                mbit = float(mbit_text)
            except (TypeError, ValueError):
                continue
            proto = _text(raw, "proto", "tcp")
            impl = _text(raw, "impl", "unknown")
            if not impl:
                continue
            mode = _text(raw, "mode", "1c")
            conns = _int(raw, "conns", 1)
            loss = _float(raw, "loss", 0.0)
            obf = _text(raw, "obf", "0")
            peers = _int(raw, "peers", 1)
            extra = _text(raw, "extra", "")
            run = _text(raw, "run", "")
            repeat = _int(raw, "repeat", 0)
            if proto == "udp":
                lost_percent = _opt_float(raw, "lost_percent")
                if lost_percent is None:
                    lost_percent = _opt_float(extra)
                loss_value = lost_percent
            else:
                loss_value = _opt_float(extra)
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
                    loss_value=loss_value,
                )
            )
    return rows


def cell_key(row: Row) -> CellKey:
    return CellKey(
        impl=row.impl,
        mode=row.mode,
        proto=row.proto,
        conns=row.conns,
        loss=row.loss,
        obf=row.obf,
        peers=row.peers,
    )


def aggregate(rows: Sequence[Row]) -> dict[CellKey, Stat]:
    buckets: dict[CellKey, list[Row]] = {}
    for row in rows:
        buckets.setdefault(cell_key(row), []).append(row)
    stats: dict[CellKey, Stat] = {}
    for key, items in buckets.items():
        values = [item.mbit for item in items]
        loss_values = [item.loss_value for item in items if item.loss_value is not None]
        stats[key] = Stat(
            median=float(statistics.median(values)),
            minimum=float(min(values)),
            maximum=float(max(values)),
            count=len(values),
            median_loss=float(statistics.median(loss_values)) if loss_values else None,
        )
    return stats


def cell_sort_key(key: CellKey) -> tuple[str, str, str, int, float, str, int]:
    return (key.impl, key.mode, key.proto, key.conns, key.loss, key.obf, key.peers)


def delta_percent(candidate: float, baseline: float) -> float | None:
    if baseline == 0:
        return None
    return (candidate - baseline) / baseline * 100.0


def compare(
    baseline: Any,
    candidate: Any,
    threshold: float = 10.0,
    loss_threshold: float = LOSS_REGRESSION_THRESHOLD,
) -> list[Comparison]:
    if isinstance(baseline, Mapping):
        base_stats = baseline
    else:
        base_stats = aggregate(baseline)
    if isinstance(candidate, Mapping):
        cand_stats = candidate
    else:
        cand_stats = aggregate(candidate)

    comparisons: list[Comparison] = []
    all_keys = sorted(set(base_stats) | set(cand_stats), key=cell_sort_key)
    for key in all_keys:
        base_stat = base_stats.get(key)
        cand_stat = cand_stats.get(key)
        if base_stat is None:
            comparisons.append(Comparison(key=key, baseline=None, candidate=cand_stat, delta_percent=None, status="NEW"))
            continue
        if cand_stat is None:
            comparisons.append(Comparison(key=key, baseline=base_stat, candidate=None, delta_percent=None, status="MISSING"))
            continue
        delta = delta_percent(cand_stat.median, base_stat.median)
        regression = False
        if base_stat.median != 0:
            if delta is not None and delta < -threshold:
                regression = True
        else:
            if cand_stat.median < base_stat.median:
                regression = True
        if (
            base_stat.median_loss is not None
            and cand_stat.median_loss is not None
            and cand_stat.median_loss > base_stat.median_loss + loss_threshold
        ):
            regression = True
        if regression:
            status = "REGRESSION"
        else:
            if delta is not None and delta > threshold:
                status = "BETTER"
            else:
                status = "OK"
        comparisons.append(
            Comparison(key=key, baseline=base_stat, candidate=cand_stat, delta_percent=delta, status=status)
        )
    return comparisons


def compare_runs(*args: Any, **kwargs: Any) -> CompareResult:
    comparisons = compare(*args, **kwargs)
    threshold = float(kwargs.get("threshold", 10.0))
    has_regression = any(c.status == "REGRESSION" for c in comparisons)
    return CompareResult(comparisons=comparisons, threshold=threshold, has_regression=has_regression)


def comparison_to_dict(comp: Comparison) -> dict[str, Any]:
    return {
        "cell": comp.key.label(),
        "key": {
            "impl": comp.key.impl,
            "mode": comp.key.mode,
            "proto": comp.key.proto,
            "conns": comp.key.conns,
            "loss": comp.key.loss,
            "obf": comp.key.obf,
            "peers": comp.key.peers,
        },
        "baseline": None if comp.baseline is None else comp.baseline.median,
        "candidate": None if comp.candidate is None else comp.candidate.median,
        "baseline_mbit": None if comp.baseline is None else comp.baseline.median,
        "candidate_mbit": None if comp.candidate is None else comp.candidate.median,
        "baseline_loss": None if comp.baseline is None else comp.baseline.median_loss,
        "candidate_loss": None if comp.candidate is None else comp.candidate.median_loss,
        "delta_percent": comp.delta_percent,
        "delta": comp.delta_percent,
        "status": comp.status,
        "regression": comp.regression,
        "better": comp.better,
    }


def render_markdown(
    comparisons: Sequence[Comparison],
    threshold: float,
    baseline_path: Any = "",
    candidate_path: Any = "",
) -> str:
    lines: list[str] = []
    lines.append("# Сравнение прогонов стенда UmbraWG")
    lines.append("")
    if baseline_path or candidate_path:
        lines.append(f"- baseline: `{baseline_path}`")
        lines.append(f"- candidate: `{candidate_path}`")
        lines.append(f"- порог регрессии: {threshold:g}%")
        lines.append("")
    lines.append("| ячейка | baseline | candidate | Δ% | статус |")
    lines.append("|---|---|---|---|---|")
    for comp in comparisons:
        base_text = "-" if comp.baseline is None else f"{comp.baseline.median:.1f}"
        cand_text = "-" if comp.candidate is None else f"{comp.candidate.median:.1f}"
        if comp.delta_percent is None:
            delta_text = "-"
        else:
            delta_text = f"{comp.delta_percent:+.1f}%"
        lines.append(
            "| "
            + " | ".join(
                [
                    comp.key.label(),
                    base_text,
                    cand_text,
                    delta_text,
                    comp.status,
                ]
            )
            + " |"
        )
    lines.append("")
    total = len(comparisons)
    regressions = sum(1 for c in comparisons if c.status == "REGRESSION")
    betters = sum(1 for c in comparisons if c.status == "BETTER")
    oks = sum(1 for c in comparisons if c.status == "OK")
    missing = sum(1 for c in comparisons if c.status == "MISSING")
    new = sum(1 for c in comparisons if c.status == "NEW")
    lines.append("## Сводка")
    lines.append("")
    lines.append(f"- всего ячеек: {total}")
    lines.append(f"- совпали: {oks + regressions + betters}")
    lines.append(f"- OK: {oks}")
    lines.append(f"- REGRESSION: {regressions}")
    lines.append(f"- BETTER: {betters}")
    lines.append(f"- MISSING: {missing}")
    lines.append(f"- NEW: {new}")
    lines.append("")
    if regressions:
        lines.append("Регрессии:")
        lines.append("")
        for comp in comparisons:
            if comp.status == "REGRESSION":
                loss_info = ""
                if comp.baseline is not None and comp.candidate is not None:
                    if (
                        comp.baseline.median_loss is not None
                        and comp.candidate.median_loss is not None
                        and comp.candidate.median_loss > comp.baseline.median_loss + LOSS_REGRESSION_THRESHOLD
                    ):
                        loss_info = (
                            f" (потери: {comp.baseline.median_loss:.2f} -> "
                            f"{comp.candidate.median_loss:.2f})"
                        )
                lines.append(f"- {comp.key.label()}: {comp.delta_percent if comp.delta_percent is None else f'{comp.delta_percent:+.1f}%'}{loss_info}")
        lines.append("")
    return "\n".join(lines)


def build_json(
    comparisons: Sequence[Comparison],
    threshold: float,
    baseline_path: Any,
    candidate_path: Any,
) -> dict[str, Any]:
    rows = [comparison_to_dict(c) for c in comparisons]
    regressions = sum(1 for c in comparisons if c.status == "REGRESSION")
    betters = sum(1 for c in comparisons if c.status == "BETTER")
    oks = sum(1 for c in comparisons if c.status == "OK")
    missing = sum(1 for c in comparisons if c.status == "MISSING")
    new = sum(1 for c in comparisons if c.status == "NEW")
    return {
        "threshold": threshold,
        "baseline": str(baseline_path),
        "candidate": str(candidate_path),
        "cells": rows,
        "rows": rows,
        "comparisons": rows,
        "summary": {
            "total": len(comparisons),
            "matched": oks + regressions + betters,
            "ok": oks,
            "regression": regressions,
            "regressions": regressions,
            "better": betters,
            "better_count": betters,
            "missing": missing,
            "new": new,
            "has_regression": regressions > 0,
        },
        "has_regression": regressions > 0,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Сравнение двух прогонов стенда UmbraWG")
    parser.add_argument("baseline", type=str)
    parser.add_argument("candidate", type=str)
    parser.add_argument("--threshold", type=float, default=10.0)
    parser.add_argument("--md", type=str, default=None)
    parser.add_argument("--json", type=str, default=None)
    args = parser.parse_args(argv)

    baseline_path = Path(args.baseline)
    candidate_path = Path(args.candidate)
    if not baseline_path.is_file() or not candidate_path.is_file():
        print(f"нет файла: {args.baseline if not baseline_path.is_file() else args.candidate}", file=sys.stderr)
        return 2
    try:
        base_rows = load_rows(baseline_path)
        cand_rows = load_rows(candidate_path)
    except Exception as exc:  # pragma: no cover - defensive
        print(f"ошибка чтения CSV: {exc}", file=sys.stderr)
        return 2
    if not base_rows:
        print("пустой baseline CSV", file=sys.stderr)
        return 2
    if not cand_rows:
        print("пустой candidate CSV", file=sys.stderr)
        return 2

    comparisons = compare(base_rows, cand_rows, threshold=args.threshold)
    text = render_markdown(comparisons, args.threshold, baseline_path, candidate_path)
    print(text)
    if args.md is not None:
        Path(args.md).write_text(text, encoding="utf-8")
    if args.json is not None:
        data = build_json(comparisons, args.threshold, baseline_path, candidate_path)
        Path(args.json).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return 1 if any(c.status == "REGRESSION" for c in comparisons) else 0


# aliases for compatibility with different test expectations
load_csv = load_rows
aggregate_rows = aggregate
compare_cells = compare
compare_data = compare
compare_files = compare
run_comparison = compare_runs
cell_label = lambda key: key.label() if hasattr(key, "label") else str(key)


if __name__ == "__main__":
    raise SystemExit(main())
