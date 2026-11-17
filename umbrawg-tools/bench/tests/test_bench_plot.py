import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "bench-plot.py"
spec = importlib.util.spec_from_file_location("bench_plot", MODULE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("не удалось загрузить bench-plot.py")
plot = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plot
spec.loader.exec_module(plot)

HEADER = (
    "impl,mode,proto,conns,loss,obf,peers,mbit,extra,run,repeat,"
    "cpu_hot,cpu_total"
)
HEADER_FULL = (
    "impl,mode,proto,conns,loss,obf,peers,mbit,extra,run,repeat,"
    "lost_percent,udp_rate,udp_mode,streams,frag,cpu_hot,cpu_total"
)


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
    cpu_hot: str = "",
    cpu_total: str = "",
) -> str:
    base = f"{impl},{mode},{proto},{conns},{loss},{obf},{peers},{mbit},{extra},run1,{repeat}"
    if cpu_hot or cpu_total:
        return f"{base},{cpu_hot or '-'},{cpu_total or '-'}"
    # match header without cpu columns: no trailing
    return base


class CsvHelpers(unittest.TestCase):
    def write(self, directory: str, lines: list[str], name: str = "bench.csv") -> Path:
        path = Path(directory) / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_median_aggregation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                tmp,
                [
                    HEADER,
                    row("rust", mbit="100.0", repeat=1),
                    row("rust", mbit="300.0", repeat=2),
                    row("rust", mbit="500.0", repeat=3),
                ],
            )
            rows = plot.load_rows(path)
            stats = plot.aggregate(rows)
        self.assertEqual(len(stats), 1)
        value = next(iter(stats.values()))
        self.assertEqual(value.median, 300.0)
        self.assertEqual(value.minimum, 100.0)
        self.assertEqual(value.maximum, 500.0)
        self.assertEqual(value.count, 3)

    def test_grouping_by_proto(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                tmp,
                [
                    HEADER,
                    row("rust", proto="tcp", mbit="100.0"),
                    row("rust", proto="udp", mbit="200.0", extra="2.5"),
                ],
            )
            rows = plot.load_rows(path)
            groups = plot.group_rows(rows)
        self.assertEqual(len(groups), 2)

    def test_empty_file_no_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(tmp, [])
            rows = plot.load_rows(path)
            self.assertEqual(rows, [])
            out = Path(tmp) / "out.html"
            code = plot.main([str(path), "-o", str(out)])
            self.assertEqual(code, 1)
            self.assertFalse(out.exists())

    def test_header_only_no_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(tmp, [HEADER])
            rows = plot.load_rows(path)
            self.assertEqual(rows, [])
            code = plot.main([str(path)])
            self.assertEqual(code, 1)

    def test_broken_lines_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                tmp,
                [
                    HEADER,
                    "this is not csv",
                    "rust,1c,tcp,1,0,0,1,NOTANUMBER,0,run1,1",
                    row("rust", mbit="800.0", repeat=2),
                ],
            )
            rows = plot.load_rows(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].mbit, 800.0)

    def test_html_escaping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                tmp,
                [
                    HEADER,
                    row("<b>evil</b>", mbit="10.0"),
                ],
            )
            rows = plot.load_rows(path)
            title = "<script>alert(1)</script>"
            html_text = plot.build_report(path, rows, title)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_text)
        self.assertIn("&lt;b&gt;evil&lt;/b&gt;", html_text)
        self.assertNotIn("<script>alert(1)</script>", html_text)

    def test_cpu_verdict_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                tmp,
                [
                    HEADER,
                    row("rust", mbit="100.0", cpu_hot="1", cpu_total="98"),
                ],
            )
            rows = plot.load_rows(path)
            html_text = plot.build_report(path, rows, "t")
        self.assertIn("single-core bound", html_text)

    def test_udp_loss_highlight(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(
                tmp,
                [
                    HEADER,
                    row("rust", proto="udp", mbit="100.0", extra="3.5", repeat=1),
                ],
            )
            rows = plot.load_rows(path)
            html_text = plot.build_report(path, rows, "t")
        self.assertIn('class="warn"', html_text)
        self.assertIn("потери UDP > 1%", html_text)


if __name__ == "__main__":
    unittest.main()
