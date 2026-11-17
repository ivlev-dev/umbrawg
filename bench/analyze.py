#!/usr/bin/env python3
import argparse
import json
import struct
import sys

H1 = 712026294
H2 = 1504260570
H3 = 2938347170
H4 = 3916942126


def read_capture(path):
    recs = []
    with open(path, "rb") as f:
        data = f.read()
    off = 0
    while off + 14 <= len(data):
        ts, ln, direction, frag = struct.unpack_from("<QIbb", data, off)
        off += 14
        payload = data[off:off + ln]
        off += ln
        recs.append({"ts": ts, "dir": direction, "payload": payload, "frag": frag})
    return recs


def parse_ispec(spec):
    segs = []
    for chunk in spec.split("<")[1:]:
        if ">" not in chunk:
            break
        body = chunk.split(">")[0]
        parts = body.split(" ", 1)
        kind = parts[0]
        val = parts[1] if len(parts) > 1 else None
        if kind == "b":
            segs.append(("fixed", bytes.fromhex(val[2:])))
        elif kind in ("c", "t"):
            segs.append(("var4", b"\x00" * 4))
        elif kind in ("r", "rc", "rd"):
            segs.append((kind, b"\x00" * int(val)))
    return segs


def ispec_len(segs):
    return sum(len(s[1]) for s in segs)


def ispec_match(segs, payload):
    if len(payload) != ispec_len(segs):
        return False
    off = 0
    for kind, val in segs:
        chunk = payload[off:off + len(val)]
        if kind == "fixed" and chunk != val:
            return False
        if kind == "rc" and any(not (97 <= c <= 122 or 65 <= c <= 90) for c in chunk):
            return False
        if kind == "rd" and any(not (48 <= c <= 57) for c in chunk):
            return False
        off += len(val)
    return True


def expected_len(size, mtu=1420):
    inner = 20 + 8 + size
    pad = (inner + 15) // 16 * 16 - inner
    if inner > mtu:
        pad = ((inner % mtu) + 15) // 16 * 16 - (inner % mtu)
    return 16 + inner + pad + 16


def analyze_det(recs, expect_len, count):
    pkts = []
    errors = []
    frags = sum(1 for r in recs if r.get("frag") and r["dir"] == 0)
    if frags:
        errors.append(f"ip_fragmented_records={frags}")
    for r in recs:
        if r["dir"] != 0:
            continue
        p = r["payload"]
        if len(p) >= 4:
            typ = struct.unpack_from("<I", p, 0)[0]
            if typ in (H1, H2, H3) and len(p) <= 160:
                continue
        off = 0
        while off < len(p):
            if len(p) - off < expect_len:
                errors.append(f"short chunk {len(p) - off} at {off} rec_len={len(p)}")
                break
            chunk = p[off:off + expect_len]
            typ = struct.unpack_from("<I", chunk, 0)[0]
            if typ != H4:
                errors.append(f"bad type {typ} at {off} rec_len={len(p)}")
                break
            pkts.append({
                "key_idx": struct.unpack_from("<I", chunk, 4)[0],
                "counter": struct.unpack_from("<Q", chunk, 8)[0],
            })
            off += expect_len
    counters = [x["counter"] for x in pkts]
    sequential = all(b == a + 1 for a, b in zip(counters, counters[1:]))
    key_idx = sorted({x["key_idx"] for x in pkts})
    return {
        "ok": not errors and sequential and len(pkts) == count,
        "packets": len(pkts),
        "expected_packets": count,
        "counters_sequential": sequential,
        "first_counter": counters[0] if counters else None,
        "last_counter": counters[-1] if counters else None,
        "key_idx_count": len(key_idx),
        "errors": errors[:5],
    }


def analyze_obf(recs, ispecs, jc, jmin, jmax, max_packets):
    in_pkts = [r["payload"] for r in recs if r["dir"] == 0][:max_packets]
    out = {"junk": 0, "ispecs": {}, "unknown": 0, "max_len": 0, "min_len": 10 ** 9}
    matched_idx = set()
    for name, segs in ispecs.items():
        hits = [i for i, p in enumerate(in_pkts) if ispec_match(segs, p)]
        out["ispecs"][name] = {"expected_len": ispec_len(segs), "hits": len(hits)}
        matched_idx.update(hits)
    for i, p in enumerate(in_pkts):
        out["max_len"] = max(out["max_len"], len(p))
        out["min_len"] = min(out["min_len"], len(p))
        if i in matched_idx:
            continue
        typ = struct.unpack_from("<I", p, 0)[0] if len(p) >= 4 else None
        is_plain_hs = typ in (H1, H2, H3)
        if is_plain_hs:
            continue
        if jmin <= len(p) <= jmax:
            out["junk"] += 1
        else:
            out["unknown"] += 1
    out["ok"] = all(v["hits"] >= 1 for v in out["ispecs"].values()) and out["unknown"] == 0
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cap", required=True)
    ap.add_argument("--mode", choices=["det", "obf"], default="det")
    ap.add_argument("--sizes", default="100,300,1000,1300,1390")
    ap.add_argument("--expect-len", type=int, default=0)
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--flows", type=int, default=1)
    ap.add_argument("--mtu", type=int, default=1420)
    ap.add_argument("--jc", type=int, default=6)
    ap.add_argument("--jmin", type=int, default=292)
    ap.add_argument("--jmax", type=int, default=1152)
    ap.add_argument("--conf", default="/root/umbrawg/bench/obf-params.conf")
    ap.add_argument("--max-packets", type=int, default=12)
    args = ap.parse_args()

    recs = read_capture(args.cap)
    if args.mode == "det":
        res = analyze_det(recs, args.expect_len, args.count)
    else:
        ispecs = {}
        with open(args.conf) as f:
            for line in f:
                line = line.strip()
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k.strip() in ("I1", "I2", "I3", "I4", "I5"):
                    ispecs[k.strip()] = parse_ispec(v.strip())
        res = analyze_obf(recs, ispecs, args.jc, args.jmin, args.jmax, args.max_packets)
    res["records"] = len(recs)
    print(json.dumps(res, indent=2))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
