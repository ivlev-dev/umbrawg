import importlib.util
import sys
import unittest
from collections import Counter
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "detect.py"
spec = importlib.util.spec_from_file_location("bench_detect_golden", MODULE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("не удалось загрузить bench/detect.py")
detect = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = detect
spec.loader.exec_module(detect)

GOLDEN_PCAP = Path(__file__).resolve().parent / "golden" / "mixed-fec21.pcap"


def two_most_frequent_udp_ports(capture):
    counts = Counter()
    for packet in capture.packets:
        if packet.sport is not None:
            counts[packet.sport] += 1
        if packet.dport is not None:
            counts[packet.dport] += 1
    if len(counts) < 2:
        raise AssertionError("в pcap меньше двух различных UDP-портов")
    top = [port for port, _ in counts.most_common(2)]
    return sorted(top)


class GoldenPcap(unittest.TestCase):
    def test_golden_capture_is_clean(self):
        self.assertTrue(GOLDEN_PCAP.is_file(), f"нет golden-файла: {GOLDEN_PCAP}")
        capture = detect.read_pcap(GOLDEN_PCAP)
        self.assertGreaterEqual(len(capture.packets), 2000)
        self.assertLessEqual(len(capture.packets), 3000)

        port_a, port_b = two_most_frequent_udp_ports(capture)

        report = detect.analyze_capture(GOLDEN_PCAP, port_a, port_b, s4=0)

        self.assertIn("verdict", report)
        self.assertIn("checks", report)
        self.assertIn("metrics", report)
        self.assertIn("all", report["metrics"])

        self.assertEqual(
            report["verdict"],
            "OK",
            f"verdict={report['verdict']}, fail_count={report['fail_count']}",
        )
        self.assertEqual(report["fail_count"], 0)
        failed = [c["name"] for c in report["checks"] if c["status"] == "FAIL"]
        self.assertFalse(failed, f"FAIL в checks: {failed}")

        metrics = report["metrics"]["all"]

        self.assertLessEqual(
            metrics["max_run"],
            8,
            f"max_run={metrics['max_run']} (ожидалось <= 8)",
        )
        self.assertLessEqual(
            metrics["ack_share_window"],
            0.10,
            f"ack_share_window={metrics['ack_share_window']} (ожидалось <= 0.10)",
        )
        self.assertEqual(
            metrics["frag_share"],
            0.0,
            f"frag_share={metrics['frag_share']} (ожидалось == 0)",
        )
        self.assertLessEqual(
            metrics["top1_share"],
            0.10,
            f"top1_share={metrics['top1_share']} (ожидалось <= 0.10)",
        )
        self.assertGreaterEqual(
            metrics["mod16_entropy"],
            3.5,
            f"mod16_entropy={metrics['mod16_entropy']} (ожидалось >= 3.5)",
        )
        self.assertLessEqual(
            metrics["small_share"],
            0.30,
            f"small_share={metrics['small_share']} (ожидалось <= 0.30)",
        )
        self.assertGreaterEqual(
            metrics["interval_cv"] if metrics["interval_cv"] is not None else 0.0,
            0.3,
            f"interval_cv={metrics['interval_cv']} (ожидалось >= 0.3)",
        )
        self.assertLessEqual(
            metrics["run3_share"],
            0.15,
            f"run3_share={metrics['run3_share']} (ожидалось <= 0.15)",
        )


if __name__ == "__main__":
    unittest.main()
PY