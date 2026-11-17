import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "wakeup-analysis.py"
spec = importlib.util.spec_from_file_location("wakeup_analysis", MODULE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("не удалось загрузить wakeup-analysis.py")
analysis = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = analysis
spec.loader.exec_module(analysis)

HEADER = (
    "impl,mode,proto,conns,loss,obf,peers,mbit,extra,run,repeat,"
    "lost_percent,udp_rate,udp_mode,streams,frag,cpu_hot,cpu_total"
)


def row(
    mode: str = "1c",
    proto: str = "tcp",
    conns: int = 1,
    obf: int = 0,
    mbit: str = "100.0",
    extra: str = "0",
    run: str = "master-r1",
    lost: str = "-",
    cpu: str = "-",
) -> str:
    return (
        f"kernel-umbrawg,{mode},{proto},{conns},0,{obf},1,{mbit},{extra},"
        f"{run},1,{lost},1G,rate,{'single' if conns <= 1 else 'multi'},0,"
        f"0,{cpu}"
    )


def write_csv(path: Path, rows: list[str]) -> Path:
    path.write_text("\n".join([HEADER, *rows]) + "\n", encoding="utf-8")
    return path


class LoadTest(unittest.TestCase):
    def test_parses_fields_and_rep(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_csv(
                Path(tmp) / "ab-master.csv",
                [
                    row(mbit="2282.1", extra="1234", run="master-r3", cpu="55"),
                    row(proto="udp", mbit="998.4", extra="-", run="master-r1",
                        lost="0.125", cpu="-"),
                ],
            )
            samples = analysis.load(path, "master")

        self.assertEqual(len(samples), 2)
        tcp, udp = samples
        self.assertEqual(tcp.variant, "master")
        self.assertEqual(tcp.rep, 3)
        self.assertEqual(tcp.mbit, 2282.1)
        self.assertEqual(tcp.extra, "1234")
        self.assertEqual(tcp.lost, 0.0)
        self.assertEqual(tcp.cpu_total, 55)
        self.assertEqual(tcp.cell, ("1c", 0, 1, "tcp"))
        self.assertEqual(udp.lost, 0.125)
        self.assertEqual(udp.cpu_total, -1)

    def test_skips_failed_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_csv(
                Path(tmp) / "ab-wakeup.csv",
                [row(mbit="FAIL", run="wakeup-r1"), row(mbit="10.0")],
            )
            samples = analysis.load(path, "wakeup")

        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].mbit, 10.0)


class CompareTest(unittest.TestCase):
    def test_medians_and_paired_delta(self) -> None:
        master = [analysis.Sample("master", "1c", "tcp", 1, 0, rep, mbit, "0",
                                  0.0, -1)
                  for rep, mbit in ((1, 100.0), (2, 110.0), (3, 120.0))]
        wakeup = [analysis.Sample("wakeup", "1c", "tcp", 1, 0, rep, mbit, "0",
                                  0.0, -1)
                  for rep, mbit in ((1, 120.0), (2, 120.0), (3, 130.0))]

        results = analysis.compare(master, wakeup)

        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res.master_median, 110.0)
        self.assertEqual(res.wakeup_median, 120.0)
        self.assertAlmostEqual(res.delta, 100.0 * 10.0 / 110.0)
        self.assertEqual(len(res.deltas), 3)
        self.assertAlmostEqual(res.deltas[0], 20.0)
        self.assertEqual((res.positive, res.negative), (3, 0))

    def test_pairs_only_on_common_reps(self) -> None:
        master = [analysis.Sample("master", "3c", "tcp", 10, 1, rep, mbit, "0",
                                  0.0, -1)
                  for rep, mbit in ((1, 100.0), (2, 100.0), (3, 100.0))]
        wakeup = [analysis.Sample("wakeup", "3c", "tcp", 10, 1, rep, mbit, "0",
                                  0.0, -1)
                  for rep, mbit in ((2, 90.0), (3, 110.0))]

        res = analysis.compare(master, wakeup)[0]

        self.assertEqual(len(res.deltas), 2)
        self.assertAlmostEqual(res.deltas[0], -10.0)
        self.assertAlmostEqual(res.deltas[1], 10.0)
        self.assertEqual(res.master_median, 100.0)
        self.assertEqual((res.positive, res.negative), (1, 1))

    def test_cell_without_counterpart_is_skipped(self) -> None:
        master = [analysis.Sample("master", "1c", "tcp", 1, 0, 1, 100.0, "0",
                                  0.0, -1)]
        self.assertEqual(analysis.compare(master, []), [])

    def test_zero_master_mbit_gives_no_pairs(self) -> None:
        master = [analysis.Sample("master", "1c", "tcp", 1, 0, 1, 0.0, "0",
                                  0.0, -1)]
        wakeup = [analysis.Sample("wakeup", "1c", "tcp", 1, 0, 1, 100.0, "0",
                                  0.0, -1)]
        self.assertEqual(analysis.compare(master, wakeup), [])

    def test_extra_lost_and_cpu_formatting(self) -> None:
        master = [
            analysis.Sample("master", "1c", "tcp", 1, 0, 1, 100.0, "100",
                            -1.0, 60),
            analysis.Sample("master", "1c", "tcp", 1, 0, 2, 100.0, "300",
                            -1.0, 70),
            analysis.Sample("master", "1c", "udp", 1, 0, 1, 100.0, "-", 0.1,
                            -1),
            analysis.Sample("master", "1c", "udp", 1, 0, 2, 100.0, "-", 0.3,
                            -1),
        ]
        wakeup = [
            analysis.Sample("wakeup", "1c", "tcp", 1, 0, 1, 100.0, "50", -1.0,
                            55),
            analysis.Sample("wakeup", "1c", "tcp", 1, 0, 2, 100.0, "150",
                            -1.0, 65),
            analysis.Sample("wakeup", "1c", "udp", 1, 0, 1, 100.0, "-", 0.0,
                            -1),
            analysis.Sample("wakeup", "1c", "udp", 1, 0, 2, 100.0, "-", 0.2,
                            -1),
        ]

        results = {r.cell[3]: r for r in analysis.compare(master, wakeup)}

        self.assertEqual(results["tcp"].master_extra, "200")
        self.assertEqual(results["tcp"].wakeup_extra, "100")
        self.assertEqual(results["tcp"].master_cpu, "65")
        self.assertEqual(results["udp"].master_extra, "0.200")
        self.assertEqual(results["udp"].wakeup_extra, "0.100")
        self.assertEqual(results["udp"].master_cpu, "-")


class RenderTest(unittest.TestCase):
    def test_table_and_summary(self) -> None:
        master = [analysis.Sample("master", "1c", "tcp", 1, 0, 1, 100.0, "0",
                                  0.0, -1)]
        wakeup = [analysis.Sample("wakeup", "1c", "tcp", 1, 0, 1, 105.0, "0",
                                  0.0, -1)]

        text = analysis.render(analysis.compare(master, wakeup))
        lines = text.splitlines()

        self.assertTrue(lines[0].startswith("| mode | obf | conns | proto |"))
        self.assertIn("| 1c | 0 | 1 | tcp | 100.0 | 105.0 | +5.00 | +5.0 | "
                      "1+/0- | 0 | 0 | -/- |", lines[2])
        self.assertEqual(lines[3], "")
        self.assertIn("median paired delta across all cells: +5.00%", lines[4])
        self.assertIn("n=1", lines[4])

    def test_empty_results(self) -> None:
        text = analysis.render([])
        self.assertEqual(len(text.splitlines()), 2)


class MainTest(unittest.TestCase):
    def test_prints_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "ab"
            write_csv(Path("%s-master.csv" % base),
                      [row(mbit="100.0", run="master-r1")])
            write_csv(Path("%s-wakeup.csv" % base),
                      [row(mbit="110.0", run="wakeup-r1")])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = analysis.main([str(base)])

        self.assertEqual(code, 0)
        self.assertIn("+10.00", out.getvalue())

    def test_missing_file_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = analysis.main([str(Path(tmp) / "absent")])

        self.assertEqual(code, 1)
        self.assertIn("нет файла", err.getvalue())

    def test_help_exits_zero(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as ctx:
                analysis.main(["--help"])

        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("wakeup", out.getvalue())

    def test_short_name_resolves_to_results_dir(self) -> None:
        self.assertEqual(analysis.resolve_base("wakeup-ab"),
                         analysis.BENCH_DIR / "results" / "wakeup-ab")
        self.assertEqual(analysis.resolve_base("/tmp/x/ab"),
                         Path("/tmp/x/ab"))


if __name__ == "__main__":
    unittest.main()
