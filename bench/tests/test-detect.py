import contextlib
import importlib.util
import io
import json
import random
import struct
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "detect.py"
spec = importlib.util.spec_from_file_location("bench_detect", MODULE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("не удалось загрузить bench/detect.py")
detect = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = detect
spec.loader.exec_module(detect)

PORT_A = 51820
PORT_B = 51821
ETH = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + struct.pack("!H", 0x0800)


def ip4(addr):
    return bytes(int(x) for x in addr.split("."))


def udp_frame(payload_len, sport, dport, frag=False, src="10.0.0.1", dst="10.0.0.2"):
    payload = b"\x00" * payload_len
    udp = struct.pack("!HHHH", sport, dport, 8 + payload_len, 0) + payload
    total = 20 + len(udp)
    flags = 0x2000 if frag else 0
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, 0, flags, 64, 17, 0, ip4(src), ip4(dst)
    )
    return ETH + ip + udp


def udp6_frame(payload_len, sport, dport):
    payload = b"\x00" * payload_len
    udp = struct.pack("!HHHH", sport, dport, 8 + payload_len, 0) + payload
    src = bytes.fromhex("fd00" + "00" * 14 + "0001")
    dst = bytes.fromhex("fd00" + "00" * 14 + "0002")
    ip = struct.pack("!IHBB16s16s", 0x60000000, len(udp), 17, 64, src, dst)
    eth = ETH[:12] + struct.pack("!H", 0x86DD)
    return eth + ip + udp


def write_pcap(path, records, linktype=1, nanosecond=False, big_endian=False):
    endian = ">" if big_endian else "<"
    magic = 0xA1B23C4D if nanosecond else 0xA1B2C3D4
    denom = 1_000_000_000 if nanosecond else 1_000_000
    out = bytearray(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, linktype))
    for ts, frame in records:
        sec = int(ts)
        frac = int(round((ts - sec) * denom))
        if frac >= denom:
            sec += 1
            frac -= denom
        out += struct.pack(endian + "IIII", sec, frac, len(frame), len(frame))
        out += frame
    Path(path).write_bytes(bytes(out))


def bad_records():
    records = []
    ts = 1000.0
    for i in range(1000):
        if i < 800:
            frame = udp_frame(1024, PORT_B, PORT_A)
        else:
            frame = udp_frame(64, PORT_A, PORT_B)
        records.append((ts, frame))
        ts += 0.01
    return records


def good_records(seed=7, count=1200):
    rng = random.Random(seed)
    records = []
    ts = 500.0
    for _ in range(count):
        if rng.random() < 0.04:
            frame = udp_frame(64, PORT_B, PORT_A)
        else:
            frame = udp_frame(rng.randint(200, 1150), PORT_A, PORT_B)
        records.append((ts, frame))
        ts += rng.expovariate(1 / 0.01) + 0.0005
    return records


def status_of(report, name):
    for check in report["checks"]:
        if check["name"] == name:
            return check["status"]
    raise AssertionError(f"нет проверки {name}")


class PcapParsing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_little_endian_usec(self):
        path = self.dir / "le.pcap"
        write_pcap(path, bad_records()[:20])
        cap = detect.read_pcap(path)
        self.assertEqual(cap.endian, "little")
        self.assertFalse(cap.nanosecond)
        self.assertEqual(cap.linktype, 1)
        self.assertEqual(len(cap.packets), 20)
        self.assertEqual(cap.packets[0].size, 1024)

    def test_big_endian_nanosecond(self):
        path = self.dir / "be_ns.pcap"
        write_pcap(path, bad_records()[:20], nanosecond=True, big_endian=True)
        cap = detect.read_pcap(path)
        self.assertEqual(cap.endian, "big")
        self.assertTrue(cap.nanosecond)
        self.assertAlmostEqual(cap.packets[0].ts, 1000.0, places=6)

    def test_raw_ip_linktype(self):
        path = self.dir / "raw.pcap"
        records = [(ts, frame[14:]) for ts, frame in bad_records()[:20]]
        write_pcap(path, records, linktype=101)
        cap = detect.read_pcap(path)
        self.assertEqual(cap.linktype, 101)
        self.assertEqual(len(cap.packets), 20)

    def test_linux_sll_linktype(self):
        path = self.dir / "sll.pcap"
        sll = struct.pack("!HHH8sH", 0, 1, 6, b"\x00" * 8, 0x0800)
        records = [(ts, sll + frame[14:]) for ts, frame in bad_records()[:20]]
        write_pcap(path, records, linktype=113)
        cap = detect.read_pcap(path)
        self.assertEqual(cap.linktype, 113)
        self.assertEqual(len(cap.packets), 20)

    def test_vlan_tag_skipped(self):
        path = self.dir / "vlan.pcap"
        records = []
        for ts, frame in bad_records()[:5]:
            tagged = frame[:12] + struct.pack("!HH", 0x8100, 42) + frame[12:]
            records.append((ts, tagged))
        write_pcap(path, records)
        self.assertEqual(len(detect.read_pcap(path).packets), 5)

    def test_truncated_snaplen_uses_header_lengths(self):
        frame = udp_frame(1200, PORT_A, PORT_B)
        truncated = frame[:120]
        endian = "<"
        magic = 0xA1B2C3D4
        out = bytearray(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1))
        out += struct.pack(endian + "IIII", 1000, 0, len(truncated), len(frame))
        out += truncated
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "truncated.pcap"
            path.write_bytes(bytes(out))
            cap = detect.read_pcap(path)
        self.assertEqual(len(cap.packets), 1)
        self.assertEqual(cap.packets[0].size, 1200)

    def test_pcapng_rejected(self):
        path = self.dir / "ng.pcap"
        path.write_bytes(detect.PCAPNG_MAGIC + b"\x00" * 64)
        with self.assertRaises(detect.PcapError) as ctx:
            detect.read_pcap(path)
        self.assertIn("pcapng", str(ctx.exception))

    def test_unsupported_linktype(self):
        path = self.dir / "bad.pcap"
        write_pcap(path, bad_records()[:1], linktype=105)
        with self.assertRaises(detect.PcapError) as ctx:
            detect.read_pcap(path)
        self.assertIn("linktype", str(ctx.exception))

    def test_truncated_tail_is_tolerated(self):
        path = self.dir / "trunc.pcap"
        write_pcap(path, bad_records()[:20])
        data = path.read_bytes()
        path.write_bytes(data[:-7])
        cap = detect.read_pcap(path)
        self.assertEqual(cap.truncated_records, 1)
        self.assertEqual(len(cap.packets), 19)

    def test_ipv6_udp_parsed(self):
        path = self.dir / "v6.pcap"
        records = [(100.0 + i * 0.01, udp6_frame(300 + i, PORT_A, PORT_B)) for i in range(20)]
        write_pcap(path, records)
        cap = detect.read_pcap(path)
        self.assertEqual(len(cap.packets), 20)
        self.assertEqual(cap.packets[0].size, 300)
        self.assertEqual(cap.packets[0].sport, PORT_A)
        self.assertFalse(cap.packets[0].fragmented)

    def test_fragment_parsed_and_counted(self):
        path = self.dir / "frag.pcap"
        records = bad_records()[:5]
        records.append((1000.5, udp_frame(600, PORT_A, PORT_B, frag=True)))
        write_pcap(path, records)
        cap = detect.read_pcap(path)
        self.assertTrue(cap.packets[-1].fragmented)
        report = detect.analyze_capture(path)
        self.assertGreater(report["capture"]["fragments"], 0)


class MetricHelpers(unittest.TestCase):
    def test_entropy_bounds(self):
        self.assertEqual(detect._entropy([100, 0, 0]), 0.0)
        self.assertAlmostEqual(detect._entropy([1] * 16), 4.0, places=6)
        self.assertAlmostEqual(detect._entropy([1, 1]), 1.0, places=6)

    def test_run_stats(self):
        max_run, share = detect._run_stats([10, 10, 10, 20, 20, 30, 30, 30])
        self.assertEqual(max_run, 3)
        self.assertAlmostEqual(share, 6 / 8)

    def test_run_stats_short(self):
        max_run, share = detect._run_stats([10, 20])
        self.assertEqual(max_run, 1)
        self.assertEqual(share, 0.0)

    def test_autocorr_detects_metronome(self):
        series = [0] * 600
        for i in range(0, 600, 20):
            series[i] = 5
        self.assertGreater(detect._autocorr(series, 20), 0.9)
        self.assertLess(abs(detect._autocorr([1] * 600, 20) or 0.0), 1e-9)

    def test_autocorr_needs_overlap(self):
        self.assertIsNone(detect._autocorr([1, 2, 3, 4], 3))
        self.assertIsNone(detect._autocorr([0] * 600, 500))


class Profiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_bad_profile_fails(self):
        path = self.dir / "bad.pcap"
        write_pcap(path, bad_records())
        report = detect.analyze_capture(path, PORT_A, PORT_B)
        self.assertFalse(report["ok"])
        self.assertEqual(report["verdict"], "SUSPICIOUS")
        self.assertGreaterEqual(report["fail_count"], 4)
        all_metrics = report["metrics"]["all"]
        self.assertAlmostEqual(all_metrics["top1_share"], 0.8)
        self.assertEqual(all_metrics["mod16_entropy"], 0.0)
        self.assertEqual(all_metrics["max_run"], 800)
        self.assertAlmostEqual(all_metrics["ack_share_window"], 0.2)
        for name in (
            "top1_share",
            "ack_clock_share",
            "mod16_entropy",
            "max_run",
            "interval_cv",
        ):
            self.assertEqual(status_of(report, name), "FAIL", name)
        self.assertEqual(status_of(report, "ip_fragments"), "PASS")

    def test_good_profile_passes(self):
        path = self.dir / "good.pcap"
        write_pcap(path, good_records())
        report = detect.analyze_capture(path, PORT_A, PORT_B)
        self.assertEqual(report["verdict"], "OK")
        self.assertEqual(report["fail_count"], 0)
        for check in report["checks"]:
            self.assertNotEqual(check["status"], "FAIL", check["name"])
        all_metrics = report["metrics"]["all"]
        self.assertLess(all_metrics["top1_share"], detect.TOP1_SHARE_MAX)
        self.assertGreater(all_metrics["mod16_entropy"], detect.MOD16_ENTROPY_MIN)
        self.assertGreater(all_metrics["interval_cv"], detect.INTERVAL_CV_MIN)
        self.assertIn("a", report["metrics"])
        self.assertIn("b", report["metrics"])

    def test_directions_and_pps(self):
        path = self.dir / "bad.pcap"
        write_pcap(path, bad_records())
        report = detect.analyze_capture(path, PORT_A, PORT_B)
        self.assertEqual(report["metrics"]["a"]["packets"], 800)
        self.assertEqual(report["metrics"]["b"]["packets"], 200)
        self.assertGreater(report["metrics"]["a"]["pps"], 50.0)

    def test_no_ports_skips_direction_check(self):
        path = self.dir / "bad.pcap"
        write_pcap(path, bad_records())
        report = detect.analyze_capture(path)
        self.assertNotIn("a", report["metrics"])
        self.assertEqual(status_of(report, "ack_pps_ratio"), "SKIP")

    def test_s4_shifts_ack_reference(self):
        path = self.dir / "ack.pcap"
        records = []
        ts = 100.0
        for i in range(200):
            if i % 2:
                frame = udp_frame(92, PORT_B, PORT_A)
            else:
                frame = udp_frame(600 + (i * 16) % 400, PORT_A, PORT_B)
            records.append((ts, frame))
            ts += 0.01
        write_pcap(path, records)
        plain = detect.analyze_capture(path, PORT_A, PORT_B, s4=0)
        shifted = detect.analyze_capture(path, PORT_A, PORT_B, s4=28)
        self.assertEqual(shifted["ack_size"], 92)
        self.assertLess(plain["metrics"]["all"]["ack_share_window"], 0.05)
        self.assertGreater(shifted["metrics"]["all"]["ack_share_window"], 0.4)

    def test_fragmentation_rule_fails(self):
        path = self.dir / "frag.pcap"
        records = good_records(count=200)
        records.insert(50, (records[49][0] + 0.001, udp_frame(800, PORT_A, PORT_B, frag=True)))
        write_pcap(path, records)
        report = detect.analyze_capture(path, PORT_A, PORT_B)
        self.assertGreater(report["metrics"]["all"]["frag_share"], 0)
        self.assertEqual(status_of(report, "ip_fragments"), "FAIL")

    def test_full_mtu_relaxes_top1_for_bulk(self):
        path = self.dir / "mtu.pcap"
        rng = random.Random(3)
        records = []
        ts = 10.0
        sizes = [1452] * 120 + [2904] * 90 + [5808] * 90
        rng.shuffle(sizes)
        for size in sizes:
            frame = udp_frame(size, PORT_A, PORT_B)
            records.append((ts, frame))
            ts += rng.expovariate(1 / 100)
        write_pcap(path, records)
        report = detect.analyze_capture(path, PORT_A, PORT_B)
        self.assertGreater(report["metrics"]["all"]["full_mtu_share"], 0.9)
        # 40% одного размера: без bulk-поправки это FAIL (>0.15), с ней PASS.
        self.assertEqual(status_of(report, "top1_share"), "PASS")
        # Квантование mod 16 проверяется и на bulk: три размера -> низкая энтропия.
        self.assertEqual(status_of(report, "mod16_entropy"), "FAIL")


class Cli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = detect.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_exit_codes(self):
        bad = self.dir / "bad.pcap"
        good = self.dir / "good.pcap"
        write_pcap(bad, bad_records())
        write_pcap(good, good_records())
        self.assertEqual(self.run_cli(["--pcap", str(bad)])[0], 1)
        self.assertEqual(self.run_cli(["--pcap", str(good)])[0], 0)

    def test_json_output(self):
        path = self.dir / "bad.pcap"
        write_pcap(path, bad_records())
        code, out, _ = self.run_cli(
            ["--pcap", str(path), "--port-a", str(PORT_A), "--port-b", str(PORT_B), "--json"]
        )
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["verdict"], "SUSPICIOUS")
        self.assertEqual(data["ports"], {"a": PORT_A, "b": PORT_B})
        self.assertTrue(any(c["status"] == "FAIL" for c in data["checks"]))
        self.assertEqual(data["capture"]["udp_packets"], 1000)

    def test_human_output(self):
        path = self.dir / "good.pcap"
        write_pcap(path, good_records(count=200))
        code, out, _ = self.run_cli(["--pcap", str(path), "--port-a", str(PORT_A)])
        self.assertEqual(code, 0)
        self.assertIn("ИТОГ: OK", out)
        self.assertIn("autocorr 120s", out)

    def test_pcapng_error_exit_2(self):
        path = self.dir / "ng.pcap"
        path.write_bytes(detect.PCAPNG_MAGIC + b"\x00" * 64)
        code, out, err = self.run_cli(["--pcap", str(path)])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("pcapng", err)

    def test_bad_port_exit_2(self):
        with self.assertRaises(SystemExit) as ctx:
            self.run_cli(["--pcap", "x.pcap", "--port-a", "70000"])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
