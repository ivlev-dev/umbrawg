import csv
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "bench-compare.py"
spec = importlib.util.spec_from_file_location("bench_compare", MODULE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("не удалось загрузить bench-compare.py")
compare = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = compare
spec.loader.exec_module(compare)

HEADER = (
    "impl,mode,proto,conns,loss,obf,peers,mbit,extra,run,repeat,"
    "lost_percent,udp_rate,udp_mode,streams,frag"
)


def row(
    impl: str = "rust",
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
) -> str:
    streams = "single" if conns <= 1 else "multi"
    return (
        f"{impl},{mode},{proto},{conns},{loss},{obf},{peers},{mbit},{extra},"
        f"run1,{repeat},{lost or '-'},{rate},-,{streams},0"
    )


class CsvHelpers(unittest.TestCase):
    def write(self, directory: str, lines: list[str], name: str = "bench.csv") -> Path:
        path = Path(directory) / name
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return path

    def test_load_rows_new_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(tmp, [HEADER, row(mbit="1200.0", extra="5", lost="-")])
            rows = compare.load_rows(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].mbit, 1200.0)
        self.assertEqual(rows[0].loss_value, 5.0)

    def test_load_rows_udp_loss_from_lost_percent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                tmp,
                [HEADER, row(proto="udp", mbit="500.0", extra="1.2", lost="1.2", rate="1G")],
            )
            rows = compare.load_rows(path)
        self.assertEqual(rows[0].loss_value, 1.2)

    def test_load_rows_legacy_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                tmp,
                ["impl,mode,proto,conns,loss,obf,peers,mbit,extra", "rust,1c,udp,1,0,0,1,999.8,48.948"],
            )
            rows = compare.load_rows(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].loss_value, 48.948)

    def test_empty_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(tmp, [])
            rows = compare.load_rows(path)
        self.assertEqual(rows, [])

    def test_broken_rows_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                tmp,
                [HEADER, "not,csv", row(mbit="bad"), row(mbit="800.0", repeat=2)],
            )
            rows = compare.load_rows(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].mbit, 800.0)

    def test_missing_file_returns_empty(self) -> None:
        rows = compare.load_rows(Path(tempfile.gettempdir()) / "nope-xyz.csv")
        self.assertEqual(rows, [])


class Aggregation(unittest.TestCase):
    def test_median_aggregation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.csv"
            path.write_text(
                "\n".join(
                    [
                        HEADER,
                        row(mbit="100.0", extra="1", repeat=1),
                        row(mbit="300.0", extra="3", repeat=2),
                        row(mbit="500.0", extra="5", repeat=3),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            rows = compare.load_rows(path)
            stats = compare.aggregate(rows)
        self.assertEqual(len(stats), 1)
        value = next(iter(stats.values()))
        self.assertEqual(value.median, 300.0)
        self.assertEqual(value.median_loss, 3.0)

    def test_cell_key_includes_impl(self) -> None:
        r1 = row(impl="rust", mbit="100.0")
        r2 = row(impl="go", mbit="200.0")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.csv"
            path.write_text("\n".join([HEADER, r1, r2]) + "\n", encoding="utf-8")
            rows = compare.load_rows(path)
            stats = compare.aggregate(rows)
        self.assertEqual(len(stats), 2)


class CompareTests(unittest.TestCase):
    def make(self, base_lines, cand_lines):
        with tempfile.TemporaryDirectory() as tmp:
            bp = Path(tmp) / "base.csv"
            cp = Path(tmp) / "cand.csv"
            bp.write_text("\n".join(base_lines) + "\n", encoding="utf-8")
            cp.write_text("\n".join(cand_lines) + "\n", encoding="utf-8")
            base_rows = compare.load_rows(bp)
            cand_rows = compare.load_rows(cp)
            comps = compare.compare(base_rows, cand_rows, threshold=10.0)
            return comps

    def test_matching_regression(self) -> None:
        comps = self.make(
            [HEADER, row(mbit="1000.0", extra="0")],
            [HEADER, row(mbit="800.0", extra="0")],
        )
        self.assertEqual(len(comps), 1)
        self.assertEqual(comps[0].status, "REGRESSION")

    def test_matching_improvement(self) -> None:
        comps = self.make(
            [HEADER, row(mbit="1000.0", extra="0")],
            [HEADER, row(mbit="1200.0", extra="0")],
        )
        self.assertEqual(comps[0].status, "BETTER")

    def test_matching_ok(self) -> None:
        comps = self.make(
            [HEADER, row(mbit="1000.0", extra="0")],
            [HEADER, row(mbit="1050.0", extra="0")],
        )
        self.assertEqual(comps[0].status, "OK")

    def test_threshold_boundary(self) -> None:
        comps = self.make(
            [HEADER, row(mbit="1000.0", extra="0")],
            [HEADER, row(mbit="900.0", extra="0")],
        )
        # exactly -10% is not > threshold
        self.assertEqual(comps[0].status, "OK")
        comps2 = self.make(
            [HEADER, row(mbit="1000.0", extra="0")],
            [HEADER, row(mbit="899.0", extra="0")],
        )
        self.assertEqual(comps2[0].status, "REGRESSION")

    def test_loss_regression(self) -> None:
        comps = self.make(
            [HEADER, row(proto="udp", mbit="1000.0", extra="1.0", lost="1.0", rate="1G")],
            [HEADER, row(proto="udp", mbit="1000.0", extra="2.5", lost="2.5", rate="1G")],
        )
        self.assertEqual(comps[0].status, "REGRESSION")

    def test_loss_small_increase_ok(self) -> None:
        comps = self.make(
            [HEADER, row(proto="udp", mbit="1000.0", extra="1.0", lost="1.0", rate="1G")],
            [HEADER, row(proto="udp", mbit="1000.0", extra="1.5", lost="1.5", rate="1G")],
        )
        self.assertEqual(comps[0].status, "OK")

    def test_missing_and_new_cells(self) -> None:
        comps = self.make(
            [HEADER, row(impl="rust", mbit="1000.0"), row(impl="go", mbit="500.0")],
            [HEADER, row(impl="rust", mbit="1000.0"), row(impl="kernel-umbrawg", mbit="2000.0")],
        )
        statuses = {c.key.impl: c.status for c in comps}
        self.assertEqual(statuses["rust"], "OK")
        self.assertEqual(statuses["go"], "MISSING")
        self.assertEqual(statuses["kernel-umbrawg"], "NEW")

    def test_tcp_retransmit_regression(self) -> None:
        comps = self.make(
            [HEADER, row(mbit="1000.0", extra="0")],
            [HEADER, row(mbit="1000.0", extra="5")],
        )
        self.assertEqual(comps[0].status, "REGRESSION")

    def test_compare_accepts_stats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bp = Path(tmp) / "base.csv"
            cp = Path(tmp) / "cand.csv"
            bp.write_text("\n".join([HEADER, row(mbit="1000.0")]) + "\n", encoding="utf-8")
            cp.write_text("\n".join([HEADER, row(mbit="800.0")]) + "\n", encoding="utf-8")
            bs = compare.aggregate(compare.load_rows(bp))
            cs = compare.aggregate(compare.load_rows(cp))
            comps = compare.compare(bs, cs, threshold=10.0)
        self.assertEqual(comps[0].status, "REGRESSION")


class MainTests(unittest.TestCase):
    def test_exit_code_regression(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bp = Path(tmp) / "base.csv"
            cp = Path(tmp) / "cand.csv"
            bp.write_text("\n".join([HEADER, row(mbit="1000.0")]) + "\n", encoding="utf-8")
            cp.write_text("\n".join([HEADER, row(mbit="800.0")]) + "\n", encoding="utf-8")
            code = compare.main([str(bp), str(cp), "--threshold", "10"])
        self.assertEqual(code, 1)

    def test_exit_code_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bp = Path(tmp) / "base.csv"
            cp = Path(tmp) / "cand.csv"
            bp.write_text("\n".join([HEADER, row(mbit="1000.0")]) + "\n", encoding="utf-8")
            cp.write_text("\n".join([HEADER, row(mbit="1000.0")]) + "\n", encoding="utf-8")
            code = compare.main([str(bp), str(cp)])
        self.assertEqual(code, 0)

    def test_exit_code_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bp = Path(tmp) / "base.csv"
            bp.write_text("\n".join([HEADER, row(mbit="1000.0")]) + "\n", encoding="utf-8")
            code = compare.main([str(bp), str(Path(tmp) / "nope.csv")])
        self.assertEqual(code, 2)

    def test_exit_code_empty_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bp = Path(tmp) / "base.csv"
            cp = Path(tmp) / "cand.csv"
            bp.write_text("\n".join([HEADER]) + "\n", encoding="utf-8")
            cp.write_text("\n".join([HEADER, row(mbit="1000.0")]) + "\n", encoding="utf-8")
            code = compare.main([str(bp), str(cp)])
        self.assertEqual(code, 2)

    def test_md_and_json_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bp = Path(tmp) / "base.csv"
            cp = Path(tmp) / "cand.csv"
            md = Path(tmp) / "out.md"
            js = Path(tmp) / "out.json"
            bp.write_text("\n".join([HEADER, row(mbit="1000.0")]) + "\n", encoding="utf-8")
            cp.write_text("\n".join([HEADER, row(mbit="1200.0")]) + "\n", encoding="utf-8")
            code = compare.main([str(bp), str(cp), "--md", str(md), "--json", str(js)])
            self.assertEqual(code, 0)
            self.assertTrue(md.exists())
            self.assertTrue(js.exists())
            text = md.read_text(encoding="utf-8")
            self.assertIn("BETTER", text)
            data = json.loads(js.read_text(encoding="utf-8"))
            self.assertIn("summary", data)
            self.assertEqual(data["summary"]["better"], 1)


if __name__ == "__main__":
    unittest.main()
