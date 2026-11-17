import csv
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "bench-report.py"
spec = importlib.util.spec_from_file_location("bench_report", MODULE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("не удалось загрузить bench-report.py")
report = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = report
spec.loader.exec_module(report)

HEADER = (
    "impl,mode,proto,conns,loss,obf,peers,mbit,extra,run,repeat,"
    "lost_percent,udp_rate,udp_mode,streams,frag"
)
HEADER_CPU = HEADER + ",cpu_hot,cpu_total"


def row(
    impl: str,
    mode: str = "1c",
    proto: str = "tcp",
    conns: int = 1,
    loss: str = "0",
    obf: str = "0",
    peers: int = 1,
    mbit: str = "1000.0",
    extra: str = "0",
    repeat: int = 1,
    lost: str = "",
    rate: str = "-",
    udp_mode: str = "-",
    frag: int = 0,
    cpu_hot: str = "",
    cpu_total: str = "",
) -> str:
    streams = "single" if conns <= 1 else "multi"
    base = (
        f"{impl},{mode},{proto},{conns},{loss},{obf},{peers},{mbit},{extra},"
        f"run1,{repeat},{lost},{rate},{udp_mode},{streams},{frag}"
    )
    if cpu_hot or cpu_total:
        return f"{base},{cpu_hot or '-'},{cpu_total or '-'}"
    return base


class CsvHelpers(unittest.TestCase):
    def write(self, directory: str, lines: list[str], name: str = "bench.csv") -> Path:
        path = Path(directory) / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_new_schema_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                tmp,
                [
                    HEADER,
                    row("kernel-umbrawg", mbit="2286.8", extra="12", repeat=1),
                    row(
                        "rust",
                        proto="udp",
                        conns=10,
                        mbit="520.0",
                        extra="3.5",
                        repeat=2,
                        lost="3.5",
                        rate="1G",
                        udp_mode="fixed",
                        frag=2,
                    ),
                ],
            )
            rows = report.load_rows(path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0].mbit, 2286.8)
        self.assertEqual(rows[0].rate, "-")
        self.assertIsNone(rows[0].lost)
        self.assertEqual(rows[1].rate, "1G")
        self.assertEqual(rows[1].lost, 3.5)
        self.assertEqual(rows[1].frag, 2)
        self.assertEqual(rows[1].conns, 10)

    def test_legacy_schema_udp_loss_from_extra(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                tmp,
                [
                    "impl,mode,proto,conns,loss,obf,peers,mbit,extra",
                    "rust,1c,udp,1,0,0,1,999.8,48.948",
                ],
            )
            rows = report.load_rows(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].lost, 48.948)
        self.assertEqual(rows[0].rate, "legacy")
        self.assertEqual(rows[0].repeat, 0)

    def test_failed_rows_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                tmp,
                [
                    HEADER,
                    row("rust", mbit="FAIL"),
                    row("rust", mbit=""),
                    row("rust", mbit="800.0"),
                ],
            )
            rows = report.load_rows(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].mbit, 800.0)

    def test_empty_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(tmp, [HEADER])
            rows = report.load_rows(path)
            text = report.build_report(path, rows, None)
        self.assertEqual(rows, [])
        self.assertIn("Нет данных", text)


class Aggregation(unittest.TestCase):
    def test_median_min_max_and_loss(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bench.csv"
            path.write_text(
                "\n".join(
                    [
                        HEADER,
                        row("rust", proto="udp", mbit="100.0", extra="1.0", lost="1.0", rate="1G", repeat=1),
                        row("rust", proto="udp", mbit="300.0", extra="2.0", lost="2.0", rate="1G", repeat=2),
                        row("rust", proto="udp", mbit="500.0", extra="3.0", lost="3.0", rate="1G", repeat=3),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            rows = report.load_rows(path)
        stats = report.aggregate(rows)
        self.assertEqual(len(stats), 1)
        value = next(iter(stats.values()))
        self.assertEqual(value.median, 300.0)
        self.assertEqual(value.minimum, 100.0)
        self.assertEqual(value.maximum, 500.0)
        self.assertEqual(value.count, 3)
        self.assertEqual(value.median_lost, 2.0)

    def test_single_run_format_has_no_interval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bench.csv"
            path.write_text("\n".join([HEADER, row("go", mbit="2030.7")]) + "\n", encoding="utf-8")
            rows = report.load_rows(path)
            stats = report.aggregate(rows)
            value = next(iter(stats.values()))
        self.assertEqual(report.fmt_stat(value), "2030.7")

    def test_interval_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bench.csv"
            path.write_text(
                "\n".join(
                    [
                        HEADER,
                        row("go", mbit="100.0", repeat=1),
                        row("go", mbit="300.0", repeat=2),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            rows = report.load_rows(path)
            stats = report.aggregate(rows)
            value = next(iter(stats.values()))
        self.assertEqual(report.fmt_stat(value), "200.0 [100.0–300.0]")


class Report(unittest.TestCase):
    def build(self, lines: list[str]) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bench.csv"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            rows = report.load_rows(path)
            return report.build_report(path, rows, None)

    def test_stream_sections_and_comparison(self) -> None:
        text = self.build(
            [
                HEADER,
                row("kernel-umbrawg", mbit="1100.0"),
                row("kernel-amneziawg", mbit="1000.0"),
                row("kernel-umbrawg", conns=10, mbit="2200.0"),
                row("kernel-amneziawg", conns=10, mbit="2000.0"),
                row("rust", mbit="500.0"),
                row("go", mbit="2000.0"),
            ]
        )
        self.assertIn("1 поток (iperf3 -P 1)", text)
        self.assertIn("Много потоков (iperf3 -P > 1)", text)
        self.assertIn("+10.0%", text)
        self.assertIn("-75.0%", text)

    def test_multi_flow_udp_range_and_loss_rendered(self) -> None:
        text = self.build(
            [
                HEADER,
                row("rust", proto="udp", conns=100, mbit="500.0", lost="12.5", rate="1G", udp_mode="fixed"),
            ]
        )
        self.assertIn("udp", text)
        self.assertIn("1G", text)
        self.assertIn("loss 12.50%", text)

    def test_warnings_single_run_frag_and_overload(self) -> None:
        text = self.build(
            [
                HEADER,
                row("rust", mbit="500.0", frag=3),
                row("rust", proto="udp", mbit="100.0", lost="66.0", rate="0", udp_mode="unlimited"),
            ]
        )
        self.assertIn("без повторов", text)
        self.assertIn("фрагментация", text)
        self.assertIn("≥20%", text)

    def test_agg_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bench.csv"
            path.write_text(
                "\n".join(
                    [
                        HEADER,
                        row("go", mbit="100.0", repeat=1),
                        row("go", mbit="300.0", repeat=2),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            rows = report.load_rows(path)
            agg_path = Path(tmp) / "agg.csv"
            report.write_agg(agg_path, report.aggregate(rows))
            with agg_path.open(encoding="utf-8", newline="") as fh:
                parsed = list(csv.DictReader(fh))
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["impl"], "go")
        self.assertEqual(parsed[0]["median_mbit"], "200.0")
        self.assertEqual(parsed[0]["min_mbit"], "100.0")
        self.assertEqual(parsed[0]["max_mbit"], "300.0")
        self.assertEqual(parsed[0]["runs"], "2")


class Cpu(unittest.TestCase):
    def test_cpu_columns_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bench.csv"
            path.write_text(
                "\n".join(
                    [
                        HEADER_CPU,
                        row("kernel-umbrawg", mbit="2286.8", cpu_hot="1", cpu_total="98"),
                        row("rust", proto="udp", conns=10, mbit="818.0", rate="1G", cpu_hot="3", cpu_total="210"),
                        row("go", mbit="1000.0", cpu_hot="-", cpu_total="-"),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            rows = report.load_rows(path)
        self.assertEqual(rows[0].cpu_hot, 1)
        self.assertEqual(rows[0].cpu_total, 98.0)
        self.assertEqual(rows[1].cpu_hot, 3)
        self.assertEqual(rows[1].cpu_total, 210.0)
        self.assertIsNone(rows[2].cpu_hot)
        self.assertIsNone(rows[2].cpu_total)

    def test_cpu_columns_missing_in_legacy_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bench.csv"
            path.write_text("\n".join([HEADER, row("rust", mbit="500.0")]) + "\n", encoding="utf-8")
            rows = report.load_rows(path)
        self.assertIsNone(rows[0].cpu_hot)
        self.assertIsNone(rows[0].cpu_total)

    def test_cpu_verdict_classification(self) -> None:
        self.assertEqual(report.cpu_verdict(1, 98.0), "single-core bound")
        self.assertEqual(report.cpu_verdict(1, 95.0), "single-core bound")
        self.assertEqual(report.cpu_verdict(2, 150.0), "параллельно")
        self.assertEqual(report.cpu_verdict(0, 140.0), "параллельно")
        self.assertEqual(report.cpu_verdict(0, 20.0), "не CPU-bound")
        self.assertEqual(report.cpu_verdict(1, 60.0), "промежуточно")
        self.assertEqual(report.cpu_verdict(None, 90.0), "-")
        self.assertEqual(report.cpu_verdict(1, None), "-")

    def test_cpu_section_rendered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bench.csv"
            path.write_text(
                "\n".join(
                    [
                        HEADER_CPU,
                        row("kernel-umbrawg", mbit="2286.8", cpu_hot="1", cpu_total="99"),
                        row("kernel-umbrawg", conns=10, mbit="2318.0", cpu_hot="4", cpu_total="240"),
                        row("rust", conns=10, mbit="818.0", cpu_hot="3", cpu_total="180"),
                        row("go", conns=10, mbit="100.0", cpu_hot="0", cpu_total="20"),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            rows = report.load_rows(path)
            text = report.build_report(path, rows, None)
        self.assertIn("## Загрузка CPU", text)
        self.assertIn("single-core bound", text)
        self.assertIn("параллельно", text)
        self.assertIn("не CPU-bound", text)
        self.assertIn("99%", text)
        self.assertIn("240%", text)

    def test_cpu_section_without_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bench.csv"
            path.write_text("\n".join([HEADER, row("go", mbit="1000.0")]) + "\n", encoding="utf-8")
            rows = report.load_rows(path)
            text = report.build_report(path, rows, None)
        self.assertIn("Нет данных CPU", text)

    def test_agg_csv_cpu_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bench.csv"
            path.write_text(
                "\n".join(
                    [
                        HEADER_CPU,
                        row("go", mbit="100.0", repeat=1, cpu_hot="1", cpu_total="97"),
                        row("go", mbit="300.0", repeat=2, cpu_hot="1", cpu_total="99"),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            rows = report.load_rows(path)
            agg_path = Path(tmp) / "agg.csv"
            report.write_agg(agg_path, report.aggregate(rows))
            with agg_path.open(encoding="utf-8", newline="") as fh:
                parsed = list(csv.DictReader(fh))
        self.assertEqual(parsed[0]["cpu_hot_median"], "1")
        self.assertEqual(parsed[0]["cpu_total_median"], "98")
        self.assertEqual(parsed[0]["cpu_verdict"], "single-core bound")


if __name__ == "__main__":
    unittest.main()
