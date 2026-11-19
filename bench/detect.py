#!/usr/bin/env python3
"""Анализатор pcap для оценки детектируемости UDP-туннеля (DPI-resistance).

Читает классический pcap (Ethernet, DLT_RAW, Linux SLL), считает метрики
размеров и таймингов outer-пакетов и прогоняет rule-based проверки.

Код возврата: 0 — OK, 1 — есть подозрительные метрики, 2 — ошибка разбора.

Метрики считаются по UDP payload (размер туннельной датаграммы), то есть по
тому, что видит DPI в полезной нагрузке внешнего UDP-пакета.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence, TypedDict

# --- пороги правил (rule-based, обоснование — в bench/README.md) ---

TOP1_SHARE_MAX = 0.15           # доля самого частого outer-размера при не-full-MTU нагрузке
TOP1_SHARE_MAX_FULL_MTU = 0.50  # то же, когда >=50% пакетов упираются в MTU
FULL_MTU_SHARE_MIN = 0.20       # доля крупных пакетов, при которой это bulk-поток
FULL_MTU_MEAN_MIN = 500.0       # либо средний размер, при котором это bulk-поток
FULL_MTU_SIZE = 1200            # размер UDP payload, считающийся full-MTU
ACK_WINDOW = 4                  # окно вокруг 64+s4 для ACK-часов
ACK_SHARE_MAX = 0.15            # доля пакетов в окне 64+s4
MOD16_ENTROPY_MIN = 3.5         # энтропия распределения len % 16, бит
IP_FRAG_SHARE_MAX = 0.0         # доля IP-фрагментов
MAX_RUN_MAX = 8                 # максимальная серия одинаковых размеров
RUN3_SHARE_MAX = 0.30           # доля пакетов в сериях >= 3
RUN3_SHARE_MAX_FULL_MTU = 0.65  # bulk: равные сегменты неизбежны
INTERVAL_CV_MIN = 0.3           # коэффициент вариации межпакетных интервалов
AUTOCORR_ABS_MAX = 0.5          # |r| на лагах 1/2/5/10/120 секунд
SMALL_PKT_SHARE_MAX = 0.30      # доля пакетов < 100 байт
ACK_PPS_RATIO_MAX = 4.0         # перекос pps ACK-пакетов между направлениями

MIN_PACKETS_FOR_RULES = 50      # меньше — метрики недостоверны
MIN_AUTOCORR_SAMPLES = 30       # минимум перекрывающихся бинов для автокорреляции
AUTOCORR_LAGS_S = (1, 2, 5, 10, 120)
AUTOCORR_BIN_S = 0.1
AUTOCORR_MAX_BINS = 2_000_000
SMALL_PKT_SIZE = 100
TOP_HIST_LEN = 8

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
LINKTYPE_NAMES = {
    1: "DLT_EN10MB",
    12: "DLT_RAW",
    101: "DLT_RAW",
    113: "DLT_LINUX_SLL",
    276: "DLT_LINUX_SLL2",
    228: "DLT_IPV4",
    229: "DLT_IPV6",
}
SUPPORTED_LINKTYPES = frozenset(LINKTYPE_NAMES)

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
VLAN_ETHERTYPES = (0x8100, 0x88A8, 0x9100)


class PcapError(Exception):
    pass


@dataclass(frozen=True)
class ParsedFrame:
    is_udp: bool
    size: int
    sport: int | None
    dport: int | None
    fragmented: bool


@dataclass
class Packet:
    ts: float
    size: int
    sport: int | None
    dport: int | None
    fragmented: bool
    direction: str | None = None


@dataclass
class Capture:
    endian: str
    nanosecond: bool
    linktype: int
    packets: list[Packet] = field(default_factory=list)
    total_frames: int = 0
    non_ip_frames: int = 0
    non_udp_ip: int = 0
    truncated_records: int = 0
    ip_frames: int = 0
    frag_frames: int = 0


class Metrics(TypedDict, total=False):
    packets: int
    duration_s: float
    pps: float | None
    mean_size: float
    min_size: int
    max_size: int
    histogram: dict[int, int]
    top_sizes: list[dict[str, float | int]]
    top1_share: float
    full_mtu_share: float
    mod16_entropy: float
    mod16: list[int]
    ack_size: int
    ack_share: float
    ack_share_window: float
    small_share: float
    frag_share: float
    frag_packets: int
    max_run: int
    run3_share: float
    interval_mean_ms: float | None
    interval_cv: float | None
    autocorr: dict[str, float | None]
    autocorr_bin_s: float


class CheckDict(TypedDict):
    name: str
    status: str
    value: float | int | None
    threshold: str
    detail: str


class CaptureInfo(TypedDict):
    frames: int
    ip_frames: int
    udp_packets: int
    non_ip_frames: int
    non_udp_ip: int
    truncated_records: int
    unknown_direction: int
    duration_s: float
    fragments: int


class Report(TypedDict):
    pcap: str
    linktype: int
    linktype_name: str
    endian: str
    nanosecond: bool
    s4: int
    ack_size: int
    ports: dict[str, int | None]
    capture: CaptureInfo
    metrics: dict[str, Metrics]
    checks: list[CheckDict]
    fail_count: int
    ok: bool
    verdict: str


@dataclass
class Check:
    name: str
    status: str
    value: float | int | None
    threshold: str
    detail: str

    def to_dict(self) -> CheckDict:
        return {
            "name": self.name,
            "status": self.status,
            "value": self.value,
            "threshold": self.threshold,
            "detail": self.detail,
        }


def _strip_link_layer(frame: bytes, linktype: int) -> tuple[int, int] | None:
    if linktype == 1:
        if len(frame) < 14:
            return None
        etype = struct.unpack_from("!H", frame, 12)[0]
        off = 14
        while etype in VLAN_ETHERTYPES:
            if len(frame) < off + 4:
                return None
            etype = struct.unpack_from("!H", frame, off + 2)[0]
            off += 4
        return off, etype
    if linktype in (12, 101, 228, 229):
        if not frame:
            return None
        version = frame[0] >> 4
        if version == 4:
            return 0, ETHERTYPE_IPV4
        if version == 6:
            return 0, ETHERTYPE_IPV6
        return None
    if linktype == 113:
        if len(frame) < 16:
            return None
        return 16, struct.unpack_from("!H", frame, 14)[0]
    if linktype == 276:
        if len(frame) < 20:
            return None
        return 20, struct.unpack_from("!H", frame, 0)[0]
    return None


def _parse_ipv4(data: bytes) -> ParsedFrame | None:
    if len(data) < 20 or (data[0] >> 4) != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total = struct.unpack_from("!H", data, 2)[0]
    frag = struct.unpack_from("!H", data, 6)[0]
    # Header lengths are authoritative: a capture with a small snaplen
    # truncates the frame, but the IP/UDP headers still carry the real size.
    header_end = total if total >= ihl else len(data)
    fragmented = bool(frag & 0x2000) or bool(frag & 0x1FFF)
    proto = data[9]
    if proto != 17:
        return ParsedFrame(False, max(0, header_end - ihl), None, None, fragmented)
    if frag & 0x1FFF:
        return ParsedFrame(False, max(0, header_end - ihl), None, None, True)
    if len(data) < ihl + 8 or header_end < ihl + 8:
        return ParsedFrame(False, 0, None, None, fragmented)
    sport, dport, ulen = struct.unpack_from("!HHH", data, ihl)
    avail = header_end - ihl - 8
    payload = min(ulen - 8, avail) if ulen >= 8 else 0
    return ParsedFrame(True, max(0, payload), sport, dport, fragmented)


def _parse_ipv6(data: bytes) -> ParsedFrame | None:
    if len(data) < 40 or (data[0] >> 4) != 6:
        return None
    plen = struct.unpack_from("!H", data, 4)[0]
    end = min(len(data), 40 + plen) if plen else len(data)
    nh = data[6]
    off = 40
    fragmented = False
    for _ in range(8):
        if nh == 17:
            break
        if nh in (0, 43, 60):
            if off + 2 > end:
                return None
            nh, hlen = data[off], (data[off + 1] + 1) * 8
            off += hlen
            continue
        if nh == 44:
            if off + 8 > end:
                return None
            frag_field = struct.unpack_from("!H", data, off + 2)[0]
            fragmented = True
            if frag_field & 0xFFF8:
                return ParsedFrame(False, max(0, end - off), None, None, True)
            nh = data[off]
            off += 8
            continue
        return ParsedFrame(False, max(0, end - 40), None, None, fragmented)
    if nh != 17:
        return ParsedFrame(False, max(0, end - 40), None, None, fragmented)
    if off + 8 > end:
        return ParsedFrame(False, 0, None, None, fragmented)
    sport, dport, ulen = struct.unpack_from("!HHH", data, off)
    header_end = 40 + plen if plen else len(data)
    avail = header_end - off - 8
    payload = min(ulen - 8, avail) if ulen >= 8 else 0
    return ParsedFrame(True, max(0, payload), sport, dport, fragmented)


def parse_frame(frame: bytes, linktype: int) -> ParsedFrame | None:
    stripped = _strip_link_layer(frame, linktype)
    if stripped is None:
        return None
    off, etype = stripped
    data = frame[off:]
    if etype == ETHERTYPE_IPV4:
        return _parse_ipv4(data)
    if etype == ETHERTYPE_IPV6:
        return _parse_ipv6(data)
    return None


def read_pcap(path: str | Path) -> Capture:
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 4:
        raise PcapError("файл пуст или короче 4 байт")
    if data[:4] == PCAPNG_MAGIC:
        raise PcapError(
            "pcapng не поддерживается: переснимите дамп классическим pcap "
            "(tcpdump -w file.pcap без -P/--pcapng) или сконвертируйте: "
            "editcap -F pcap in.pcapng out.pcap"
        )
    magic = data[:4]
    if magic not in PCAP_MAGICS:
        raise PcapError(
            f"неизвестный magic {magic.hex()}: это не классический pcap "
            "(ожидались a1b2c3d4/a1b23c4d или их little-endian варианты)"
        )
    endian, frac_denom = PCAP_MAGICS[magic]
    if len(data) < 24:
        raise PcapError("обрезанный заголовок pcap (нужно 24 байта)")
    _, _, _, _, _, linktype = struct.unpack_from(endian + "HHIIII", data, 4)
    if linktype not in SUPPORTED_LINKTYPES:
        raise PcapError(
            f"неподдерживаемый linktype {linktype}: поддержаны Ethernet (1), "
            "DLT_RAW (12/101/228/229) и Linux SLL/SLL2 (113/276)"
        )

    cap = Capture(
        endian="big" if endian == ">" else "little",
        nanosecond=frac_denom == 1_000_000_000,
        linktype=linktype,
    )
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl, _orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        if incl > len(data) - off:
            cap.truncated_records += 1
            break
        frame = data[off:off + incl]
        off += incl
        cap.total_frames += 1
        parsed = parse_frame(frame, linktype)
        if parsed is None:
            cap.non_ip_frames += 1
            continue
        cap.ip_frames += 1
        if parsed.fragmented:
            cap.frag_frames += 1
        if not parsed.is_udp:
            cap.non_udp_ip += 1
            continue
        cap.packets.append(
            Packet(
                ts=ts_sec + ts_frac / frac_denom,
                size=parsed.size,
                sport=parsed.sport,
                dport=parsed.dport,
                fragmented=parsed.fragmented,
            )
        )
    if not cap.packets:
        raise PcapError(
            f"в pcap нет UDP-пакетов (кадров {cap.total_frames}, "
            f"не-IP {cap.non_ip_frames}, не-UDP IP {cap.non_udp_ip})"
        )
    return cap


def _entropy(counts: Sequence[int]) -> float:
    total = sum(counts)
    if total <= 0:
        return 0.0
    value = 0.0
    for count in counts:
        if count:
            p = count / total
            value -= p * math.log2(p)
    return value


def _run_stats(sizes: Sequence[int]) -> tuple[int, float]:
    if not sizes:
        return 0, 0.0
    max_run = 0
    in_runs = 0
    run = 1
    for prev, cur in zip(sizes, sizes[1:]):
        if cur == prev:
            run += 1
            continue
        max_run = max(max_run, run)
        if run >= 3:
            in_runs += run
        run = 1
    max_run = max(max_run, run)
    if run >= 3:
        in_runs += run
    return max_run, in_runs / len(sizes)


def _cv(intervals: Sequence[float]) -> float | None:
    if len(intervals) < 2:
        return None
    mean = statistics.fmean(intervals)
    if mean <= 0:
        return None
    return statistics.pstdev(intervals) / mean


def _binned_counts(times: Sequence[float], bin_s: float) -> tuple[list[int], float]:
    if not times:
        return [], bin_s
    span = times[-1] - times[0]
    count = int(span / bin_s) + 1
    if count > AUTOCORR_MAX_BINS:
        bin_s = span / (AUTOCORR_MAX_BINS - 1)
        count = AUTOCORR_MAX_BINS
    counts = [0] * max(count, 1)
    last = len(counts) - 1
    for t in times:
        idx = int((t - times[0]) / bin_s)
        counts[min(idx, last)] += 1
    return counts, bin_s


def _autocorr(series: Sequence[int], lag: int) -> float | None:
    if lag <= 0 or lag >= len(series) - MIN_AUTOCORR_SAMPLES + 1:
        return None
    a = series[:-lag]
    b = series[lag:]
    n = len(a)
    if n < MIN_AUTOCORR_SAMPLES:
        return None
    mean_a = statistics.fmean(a)
    mean_b = statistics.fmean(b)
    var_a = sum((x - mean_a) ** 2 for x in a)
    var_b = sum((y - mean_b) ** 2 for y in b)
    if var_a <= 0 or var_b <= 0:
        return None
    cov = sum((x - mean_a) * (y - mean_b) for x, y in zip(a, b))
    return cov / math.sqrt(var_a * var_b)


def _top_sizes(sizes: Sequence[int]) -> list[dict[str, float | int]]:
    counter = Counter(sizes)
    total = len(sizes)
    return [
        {"size": size, "count": count, "share": count / total}
        for size, count in counter.most_common(TOP_HIST_LEN)
    ]


def group_metrics(
    sizes: Sequence[int],
    times: Sequence[float],
    ack_size: int,
    frag_packets: int,
    bin_seconds: float = AUTOCORR_BIN_S,
) -> Metrics:
    count = len(sizes)
    if count == 0:
        return {"packets": 0}
    ordered_times = sorted(times)
    duration = ordered_times[-1] - ordered_times[0]
    intervals = [
        cur - prev for prev, cur in zip(ordered_times, ordered_times[1:])
    ]
    counter = Counter(sizes)
    ack_lo = ack_size - ACK_WINDOW
    ack_hi = ack_size + ACK_WINDOW
    ack_window = sum(c for s, c in counter.items() if ack_lo <= s <= ack_hi)
    mod16 = [0] * 16
    for size in sizes:
        mod16[size % 16] += 1
    max_run, run3_share = _run_stats(sizes)
    binned, bin_s = _binned_counts(ordered_times, bin_seconds)
    autocorr: dict[str, float | None] = {}
    for lag_s in AUTOCORR_LAGS_S:
        lag_bins = int(round(lag_s / bin_s))
        autocorr[f"{lag_s}s"] = _autocorr(binned, lag_bins)
    full_mtu = sum(c for s, c in counter.items() if s >= FULL_MTU_SIZE)
    return {
        "packets": count,
        "duration_s": duration,
        "pps": count / duration if duration > 0 else None,
        "mean_size": statistics.fmean(sizes),
        "min_size": min(sizes),
        "max_size": max(sizes),
        "histogram": dict(sorted(counter.items())),
        "top_sizes": _top_sizes(sizes),
        "top1_share": counter.most_common(1)[0][1] / count,
        "full_mtu_share": full_mtu / count,
        "mod16_entropy": _entropy(mod16),
        "mod16": mod16,
        "ack_size": ack_size,
        "ack_share": counter.get(ack_size, 0) / count,
        "ack_share_window": ack_window / count,
        "small_share": sum(c for s, c in counter.items() if s < SMALL_PKT_SIZE)
        / count,
        "frag_share": frag_packets / count,
        "frag_packets": frag_packets,
        "max_run": max_run,
        "run3_share": run3_share,
        "interval_mean_ms": statistics.fmean(intervals) * 1000.0
        if intervals
        else None,
        "interval_cv": _cv(intervals),
        "autocorr": autocorr,
        "autocorr_bin_s": bin_s,
    }


def _direction(packet: Packet, port_a: int | None, port_b: int | None) -> str | None:
    if port_a is not None and port_b is not None:
        if packet.dport == port_a:
            return "a"
        if packet.dport == port_b:
            return "b"
        return None
    if port_a is not None:
        if packet.dport == port_a:
            return "a"
        if packet.sport == port_a:
            return "b"
        return None
    if port_b is not None:
        if packet.dport == port_b:
            return "b"
        if packet.sport == port_b:
            return "a"
    return None


def _check(
    name: str,
    value: float | int | None,
    ok: bool | None,
    threshold: str,
    detail: str,
) -> Check:
    if ok is None or value is None:
        status = "SKIP"
    else:
        status = "PASS" if ok else "FAIL"
    return Check(name, status, value, threshold, detail)


def evaluate(
    metrics: Metrics, direction_metrics: dict[str, Metrics]
) -> list[Check]:
    count = metrics.get("packets", 0)
    fails_guard = count < MIN_PACKETS_FOR_RULES
    checks: list[Check] = [
        _check(
            "capture_size",
            count,
            not fails_guard,
            f">= {MIN_PACKETS_FOR_RULES}",
            "мало пакетов: метрики недостоверны" if fails_guard else "объём достаточен",
        )
    ]
    if count == 0:
        return checks

    full_mtu_share = metrics["full_mtu_share"]
    mean_size = metrics.get("mean_size") or 0.0
    # Bulk-поток: много крупных пакетов или большой средний размер. Для
    # такого трафика доминирование одного размера и серии равных сегментов
    # — свойство самого TCP, а не обфускации.
    full_mtu = full_mtu_share >= FULL_MTU_SHARE_MIN or mean_size >= FULL_MTU_MEAN_MIN
    top1_share = metrics["top1_share"]
    if full_mtu:
        checks.append(
            _check(
                "top1_share",
                top1_share,
                top1_share <= TOP1_SHARE_MAX_FULL_MTU,
                f"<= {TOP1_SHARE_MAX_FULL_MTU:.2f} (full-MTU)",
                f"full-MTU нагрузка ({full_mtu_share:.2f} пакетов >= {FULL_MTU_SIZE} B), "
                "доминирование одного размера ожидаемо",
            )
        )
    else:
        checks.append(
            _check(
                "top1_share",
                top1_share,
                top1_share <= TOP1_SHARE_MAX,
                f"<= {TOP1_SHARE_MAX:.2f}",
                "доля самого частого размера; высокое значение — фиксированный профиль",
            )
        )

    ack_share = metrics["ack_share_window"]
    ack_size = metrics["ack_size"]
    checks.append(
        _check(
            "ack_clock_share",
            ack_share,
            ack_share <= ACK_SHARE_MAX,
            f"<= {ACK_SHARE_MAX:.2f}",
            f"доля пакетов {ack_size}±{ACK_WINDOW} B (ACK-часы, 64+s4)",
        )
    )

    entropy = metrics["mod16_entropy"]
    checks.append(
        _check(
            "mod16_entropy",
            entropy,
            entropy >= MOD16_ENTROPY_MIN,
            f">= {MOD16_ENTROPY_MIN:.1f}",
            "энтропия len%16: низкая — размеры квантуются (паддинг до 16)",
        )
    )

    frag_share = metrics["frag_share"]
    checks.append(
        _check(
            "ip_fragments",
            frag_share,
            frag_share <= IP_FRAG_SHARE_MAX,
            f"<= {IP_FRAG_SHARE_MAX:.2f}",
            "IP-фрагменты сами по себе аномалия и ломают обфускацию",
        )
    )

    max_run = metrics["max_run"]
    checks.append(
        _check(
            "max_run",
            max_run,
            max_run <= MAX_RUN_MAX,
            f"<= {MAX_RUN_MAX}",
            "максимальная серия одинаковых размеров подряд",
        )
    )

    run3_share = metrics["run3_share"]
    # Bulk-поток (TCP) сам по себе состоит из равных сегментов, поэтому
    # порог ослаблен так же, как для top-1 при full-MTU нагрузке.
    if full_mtu:
        checks.append(
            _check(
                "run3_share",
                run3_share,
                run3_share <= RUN3_SHARE_MAX_FULL_MTU,
                f"<= {RUN3_SHARE_MAX_FULL_MTU:.2f} (full-MTU)",
                "серии одинаковых размеров: bulk-нагрузка, равные сегменты ожидаемы",
            )
        )
    else:
        checks.append(
            _check(
                "run3_share",
                run3_share,
                run3_share <= RUN3_SHARE_MAX,
                f"<= {RUN3_SHARE_MAX:.2f}",
                "доля пакетов в сериях одинакового размера >= 3",
            )
        )

    interval_cv = metrics.get("interval_cv")
    checks.append(
        _check(
            "interval_cv",
            interval_cv,
            interval_cv >= INTERVAL_CV_MIN if interval_cv is not None else None,
            f">= {INTERVAL_CV_MIN:.1f}",
            "CV межпакетных интервалов: низкий — метроном/пейсинг с постоянным шагом",
        )
    )

    autocorr = metrics.get("autocorr", {})
    worst_lag: str | None = None
    worst_value: float | None = None
    for lag, value in autocorr.items():
        if value is None:
            continue
        if worst_value is None or abs(value) > abs(worst_value):
            worst_lag, worst_value = lag, float(value)
    checks.append(
        _check(
            "autocorr",
            worst_value,
            abs(worst_value) <= AUTOCORR_ABS_MAX if worst_value is not None else None,
            f"|r| <= {AUTOCORR_ABS_MAX:.1f}",
            f"макс. |r| по лагам 1/2/5/10/120 c"
            + (f" (лаг {worst_lag})" if worst_lag else "; ряд слишком короткий"),
        )
    )

    small_share = metrics["small_share"]
    checks.append(
        _check(
            "small_packets",
            small_share,
            small_share <= SMALL_PKT_SHARE_MAX,
            f"<= {SMALL_PKT_SHARE_MAX:.2f}",
            f"доля пакетов < {SMALL_PKT_SIZE} B",
        )
    )

    if "a" in direction_metrics and "b" in direction_metrics:
        a = direction_metrics["a"]
        b = direction_metrics["b"]
        ack_pps_a = _ack_pps(a)
        ack_pps_b = _ack_pps(b)
        if ack_pps_a is None or ack_pps_b is None:
            checks.append(
                _check(
                    "ack_pps_ratio",
                    None,
                    None,
                    f"<= {ACK_PPS_RATIO_MAX:.1f}",
                    "недостаточно данных по направлениям",
                )
            )
        else:
            low = min(ack_pps_a, ack_pps_b)
            high = max(ack_pps_a, ack_pps_b)
            ratio = high / low if low > 0 else None
            checks.append(
                _check(
                    "ack_pps_ratio",
                    ratio,
                    ratio <= ACK_PPS_RATIO_MAX if ratio is not None else None,
                    f"<= {ACK_PPS_RATIO_MAX:.1f}",
                    "перекос pps ACK-пакетов между направлениями"
                    + ("" if ratio is not None else " (в одну сторону ACK нет)"),
                )
            )
    else:
        checks.append(
            _check(
                "ack_pps_ratio",
                None,
                None,
                f"<= {ACK_PPS_RATIO_MAX:.1f}",
                "направления неизвестны: укажите --port-a/--port-b",
            )
        )
    return checks


def _ack_pps(metrics: Metrics) -> float | None:
    duration = metrics.get("duration_s")
    pps = metrics.get("pps")
    if not duration or not pps:
        return None
    ack_share = metrics.get("ack_share_window")
    if ack_share is None:
        return None
    return pps * ack_share


def analyze_capture(
    path: str | Path,
    port_a: int | None = None,
    port_b: int | None = None,
    s4: int = 0,
    bin_seconds: float = AUTOCORR_BIN_S,
) -> Report:
    cap = read_pcap(path)
    if bin_seconds <= 0:
        raise PcapError("шаг бининга должен быть > 0")
    if s4 < 0:
        raise PcapError("--s4 должен быть >= 0")
    ack_size = 64 + s4
    for packet in cap.packets:
        packet.direction = _direction(packet, port_a, port_b)

    groups: dict[str, list[Packet]] = {"all": list(cap.packets)}
    if port_a is not None or port_b is not None:
        groups["a"] = [p for p in cap.packets if p.direction == "a"]
        groups["b"] = [p for p in cap.packets if p.direction == "b"]

    raw_metrics: dict[str, Metrics] = {
        key: group_metrics(
            [p.size for p in packets],
            [p.ts for p in packets],
            ack_size,
            sum(1 for p in packets if p.fragmented),
            bin_seconds,
        )
        for key, packets in groups.items()
    }

    all_metrics = raw_metrics["all"]
    capture_frag_share = (
        cap.frag_frames / cap.ip_frames if cap.ip_frames else 0.0
    )
    all_metrics["frag_packets"] = cap.frag_frames
    all_metrics["frag_share"] = capture_frag_share
    checks = evaluate(all_metrics, {k: v for k, v in raw_metrics.items() if k != "all"})
    failed = [c for c in checks if c.status == "FAIL"]
    times = [p.ts for p in cap.packets]
    duration = max(times) - min(times)
    return {
        "pcap": str(path),
        "linktype": cap.linktype,
        "linktype_name": LINKTYPE_NAMES.get(cap.linktype, str(cap.linktype)),
        "endian": cap.endian,
        "nanosecond": cap.nanosecond,
        "s4": s4,
        "ack_size": ack_size,
        "ports": {"a": port_a, "b": port_b},
        "capture": {
            "frames": cap.total_frames,
            "ip_frames": cap.ip_frames,
            "udp_packets": len(cap.packets),
            "non_ip_frames": cap.non_ip_frames,
            "non_udp_ip": cap.non_udp_ip,
            "truncated_records": cap.truncated_records,
            "unknown_direction": sum(1 for p in cap.packets if p.direction is None),
            "duration_s": duration,
            "fragments": cap.frag_frames,
        },
        "metrics": raw_metrics,
        "checks": [c.to_dict() for c in checks],
        "fail_count": len(failed),
        "ok": not failed,
        "verdict": "OK" if not failed else "SUSPICIOUS",
    }


def _fmt(value: object, digits: int = 3) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    widths = [len(h) for h in header]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    lines = [
        "  ".join(h.ljust(widths[i]) for i, h in enumerate(header)),
        "  ".join("-" * widths[i] for i in range(len(header))),
    ]
    for row in rows:
        lines.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
    return "\n".join(lines)


def format_report(report: Report) -> str:
    cap = report["capture"]
    metrics = report["metrics"]
    ports = report["ports"]
    cols = ["Все"]
    keys = ["all"]
    if "a" in metrics:
        cols += ["→A", "→B"]
        keys += ["a", "b"]
    rows: list[list[str]] = []

    def add(label: str, getter: Callable[[Metrics], str]) -> None:
        rows.append([label] + [getter(metrics[k]) for k in keys])

    add("Пакетов", lambda m: _fmt(m.get("packets")))
    add("Окно, с", lambda m: _fmt(m.get("duration_s")))
    add("PPS", lambda m: _fmt(m.get("pps"), 1))
    add("Средний размер, B", lambda m: _fmt(m.get("mean_size"), 1))
    add(
        "top-1 размер",
        lambda m: "-"
        if not m.get("top_sizes")
        else f"{m['top_sizes'][0]['size']} / {m['top1_share']:.3f}",
    )
    add("энтропия len%16", lambda m: _fmt(m.get("mod16_entropy")))
    add(
        "ACK %d±%d" % (int(report["ack_size"]), ACK_WINDOW),
        lambda m: _fmt(m.get("ack_share_window")),
    )
    add("< %d B" % SMALL_PKT_SIZE, lambda m: _fmt(m.get("small_share")))
    add("IP-фрагменты", lambda m: _fmt(m.get("frag_share")))
    add("макс. серия", lambda m: _fmt(m.get("max_run")))
    add("серии >= 3", lambda m: _fmt(m.get("run3_share")))
    add("CV интервалов", lambda m: _fmt(m.get("interval_cv")))
    for lag in AUTOCORR_LAGS_S:
        add(
            "autocorr %ds" % lag,
            lambda m, lag=lag: _fmt((m.get("autocorr") or {}).get(f"{lag}s")),
        )

    lines = [
        f"pcap:      {report['pcap']}",
        "формат:    pcap %s-endian, %s, %s (%d)"
        % (
            report["endian"],
            "nsec" if report["nanosecond"] else "usec",
            report["linktype_name"],
            report["linktype"],
        ),
        "пакеты:    UDP %d из %d кадров (не-IP %d, не-UDP IP %d, обрезано %d)"
        % (
            cap["udp_packets"],
            cap["frames"],
            cap["non_ip_frames"],
            cap["non_udp_ip"],
            cap["truncated_records"],
        ),
        "окно:      %.3f с, IP-кадров %d, фрагментов %d, без направления %d"
        % (
            cap["duration_s"],
            cap["ip_frames"],
            cap["fragments"],
            cap["unknown_direction"],
        ),
        "порты:     a=%s b=%s"
        % (
            ports["a"] if ports["a"] is not None else "-",
            ports["b"] if ports["b"] is not None else "-",
        ),
        "s4:        %d (ACK-эталон %d B, окно ±%d)"
        % (report["s4"], report["ack_size"], ACK_WINDOW),
        "",
        _table(["Метрика"] + cols, rows),
        "",
        "Проверки:",
    ]
    for check in report["checks"]:
        value = _fmt(check["value"])
        lines.append(
            "[%s] %-18s %10s  %-18s %s"
            % (check["status"], check["name"], value, check["threshold"], check["detail"])
        )
    statuses = Counter(c["status"] for c in report["checks"])
    lines += [
        "",
        "ИТОГ: %s (FAIL %d, PASS %d, SKIP %d) — exit %d"
        % (
            report["verdict"],
            statuses["FAIL"],
            statuses["PASS"],
            statuses["SKIP"],
            0 if report["ok"] else 1,
        ),
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Оценка детектируемости UDP-туннеля по pcap (rule-based)",
    )
    ap.add_argument("--pcap", required=True, help="классический pcap (tcpdump -w)")
    ap.add_argument("--port-a", type=int, help="UDP-порт стороны A")
    ap.add_argument("--port-b", type=int, help="UDP-порт стороны B")
    ap.add_argument(
        "--s4",
        type=int,
        default=0,
        help="размер S4-префикса профиля обфускации (ACK=64+s4)",
    )
    ap.add_argument("--json", action="store_true", dest="as_json", help="JSON вместо таблицы")
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    for name, value in (("--port-a", args.port_a), ("--port-b", args.port_b)):
        if value is not None and not 1 <= value <= 65535:
            ap.error(f"{name}: порт должен быть в диапазоне 1..65535")
    if args.s4 < 0:
        ap.error("--s4: значение должно быть >= 0")
    try:
        report = analyze_capture(
            path=args.pcap, port_a=args.port_a, port_b=args.port_b, s4=args.s4
        )
    except (OSError, PcapError) as exc:
        print(f"detect: {exc}", file=sys.stderr)
        return 2
    if args.as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(format_report(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
