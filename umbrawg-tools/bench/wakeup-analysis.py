#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

BENCH_DIR = Path(__file__).resolve().parent
DEFAULT_BASE = BENCH_DIR / "results" / "wakeup-ab"

Cell = tuple[str, int, int, str]


@dataclass(frozen=True)
class Sample:
    variant: str
    mode: str
    proto: str
    conns: int
    obf: int
    rep: int
    mbit: float
    extra: str
    lost: float
    cpu_total: int

    @property
    def cell(self) -> Cell:
        return (self.mode, self.obf, self.conns, self.proto)


@dataclass(frozen=True)
class CellResult:
    cell: Cell
    master_median: float
    wakeup_median: float
    delta: float
    deltas: tuple[float, ...]
    master_extra: str
    wakeup_extra: str
    master_cpu: str
    wakeup_cpu: str

    @property
    def positive(self) -> int:
        return sum(1 for d in self.deltas if d > 0)

    @property
    def negative(self) -> int:
        return sum(1 for d in self.deltas if d < 0)


def _number(text: str, default: float) -> float:
    if text in ("", "-"):
        return default
    return float(text)


def load(path: Path, variant: str) -> list[Sample]:
    samples: list[Sample] = []
    with path.open(newline="", encoding="utf-8") as fh:
        for raw in csv.DictReader(fh):
            if (raw.get("mbit") or "") == "FAIL":
                continue
            rep_text = (raw.get("run") or "").rsplit("-r", 1)[-1]
            samples.append(Sample(
                variant=variant,
                mode=raw["mode"],
                proto=raw["proto"],
                conns=int(raw["conns"]),
                obf=int(raw["obf"]),
                rep=int(rep_text),
                mbit=float(raw["mbit"]),
                extra=raw.get("extra") or "-",
                lost=_number(raw.get("lost_percent") or "-", 0.0),
                cpu_total=int(_number(raw.get("cpu_total") or "-", -1.0)),
            ))
    return samples


def group(rows: Iterable[Sample]) -> dict[Cell, dict[int, Sample]]:
    grouped: dict[Cell, dict[int, Sample]] = {}
    for row in rows:
        grouped.setdefault(row.cell, {})[row.rep] = row
    return grouped


def paired_deltas(master: dict[int, Sample],
                  wakeup: dict[int, Sample]) -> list[float]:
    deltas: list[float] = []
    for rep in sorted(set(master) & set(wakeup)):
        base = master[rep].mbit
        if base > 0:
            deltas.append(100.0 * (wakeup[rep].mbit - base) / base)
    return deltas


def fmt_extra(rows: Iterable[Sample], proto: str) -> str:
    row_list = list(rows)
    if proto == "tcp":
        values = [float(r.extra) for r in row_list
                  if r.extra not in ("", "-")]
        return "%.0f" % statistics.median(values) if values else "-"
    values = [r.lost for r in row_list]
    return "%.3f" % statistics.median(values) if values else "-"


def fmt_cpu(rows: Iterable[Sample]) -> str:
    values = [r.cpu_total for r in rows if r.cpu_total >= 0]
    return "%.0f" % statistics.median(values) if values else "-"


def compare(master_rows: Sequence[Sample],
            wakeup_rows: Sequence[Sample]) -> list[CellResult]:
    master = group(master_rows)
    wakeup = group(wakeup_rows)
    results: list[CellResult] = []
    for cell in sorted(master, key=lambda c: (c[0], c[1], c[2], c[3])):
        if cell not in wakeup:
            continue
        deltas = paired_deltas(master[cell], wakeup[cell])
        if not deltas:
            continue
        mrows = [master[cell][rep] for rep in sorted(master[cell])]
        wrows = [wakeup[cell][rep] for rep in sorted(wakeup[cell])]
        mm = statistics.median([r.mbit for r in mrows])
        wm = statistics.median([r.mbit for r in wrows])
        results.append(CellResult(
            cell=cell,
            master_median=mm,
            wakeup_median=wm,
            delta=100.0 * (wm - mm) / mm if mm else 0.0,
            deltas=tuple(deltas),
            master_extra=fmt_extra(mrows, cell[3]),
            wakeup_extra=fmt_extra(wrows, cell[3]),
            master_cpu=fmt_cpu(mrows),
            wakeup_cpu=fmt_cpu(wrows),
        ))
    return results


def render(results: Sequence[CellResult]) -> str:
    lines = [
        "| mode | obf | conns | proto | master med | wakeup med | d%% | "
        "paired deltas %% | sign | master retr/lost | wakeup retr/lost | "
        "cpu_total m/w |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    all_deltas: list[float] = []
    for res in results:
        mode, obf, conns, proto = res.cell
        pairs = " ".join("%+.1f" % d for d in res.deltas)
        lines.append(
            "| %s | %s | %d | %s | %.1f | %.1f | %+.2f | %s | %d+/%d- | "
            "%s | %s | %s/%s |" % (
                mode, obf, conns, proto,
                res.master_median, res.wakeup_median, res.delta,
                pairs, res.positive, res.negative,
                res.master_extra, res.wakeup_extra,
                res.master_cpu, res.wakeup_cpu))
        all_deltas.extend(res.deltas)
    if all_deltas:
        lines.append("")
        lines.append(
            "median paired delta across all cells: %+.2f%% "
            "(min %+.2f, max %+.2f, n=%d)" % (
                statistics.median(all_deltas), min(all_deltas),
                max(all_deltas), len(all_deltas)))
    return "\n".join(lines)


def resolve_base(text: str) -> Path:
    base = Path(text)
    if base.parent == Path("."):
        return BENCH_DIR / "results" / base.name
    return base


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Разбор A/B прогонов коалесинга пробуждений "
                    "(master против wakeup)")
    parser.add_argument(
        "base", nargs="?", default=str(DEFAULT_BASE),
        help="префикс CSV: <base>-master.csv и <base>-wakeup.csv; "
             "короткое имя ищется в bench/results")
    args = parser.parse_args(argv)

    base = resolve_base(args.base)
    master_path = Path("%s-master.csv" % base)
    wakeup_path = Path("%s-wakeup.csv" % base)
    for path in (master_path, wakeup_path):
        if not path.is_file():
            print("нет файла: %s" % path, file=sys.stderr)
            return 1

    master = load(master_path, "master")
    wakeup = load(wakeup_path, "wakeup")
    print(render(compare(master, wakeup)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
