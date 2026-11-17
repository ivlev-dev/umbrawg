#!/usr/bin/env python3
import argparse
import json
import os
import socket
import sys
import time

WORK = "/tmp/uwgbench"


def load_env():
    with open(os.path.join(WORK, "env.json")) as f:
        return json.load(f)


def sink(flows, seconds):
    socks = []
    for fl in flows:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((fl["ip_b"], 9000))
        s.settimeout(0.5)
        socks.append(s)
    end = time.time() + seconds
    counts = {}
    while time.time() < end:
        for fl, s in zip(flows, socks):
            try:
                s.recv(65535)
                counts[fl["index"]] = counts.get(fl["index"], 0) + 1
            except socket.timeout:
                pass
    print(json.dumps({"received": counts}))
    return 0


def send(flows, sizes, count, interval_ms, seconds):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    payload = b"\xa5" * max(sizes)
    deadline = time.time() + seconds
    while sent < count and time.time() < deadline:
        size = sizes[sent % len(sizes)]
        for fl in flows:
            sock.sendto(payload[:size], (fl["ip_b"], 9000))
        sent += 1
        if interval_ms:
            time.sleep(interval_ms / 1000.0)
    print(json.dumps({"sent": sent, "flows": len(flows)}))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["sink", "send"], required=True)
    ap.add_argument("--sizes", default="100,300,1000,1300,1400")
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--interval-ms", type=float, default=2.0)
    ap.add_argument("--seconds", type=float, default=10.0)
    args = ap.parse_args()

    env = load_env()
    sizes = [int(x) for x in args.sizes.split(",") if x]
    if args.mode == "sink":
        return sink(env["flows"], args.seconds)
    return send(env["flows"], sizes, args.count, args.interval_ms, args.seconds)


if __name__ == "__main__":
    sys.exit(main())
