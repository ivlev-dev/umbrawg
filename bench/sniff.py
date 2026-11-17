#!/usr/bin/env python3
import argparse
import os
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
ETH_HLEN = 14


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", required=True)
    ap.add_argument("--ports", required=True, help="lo-hi")
    ap.add_argument("--out", required=True)
    ap.add_argument("--seconds", type=float, default=8.0)
    args = ap.parse_args()

    lo, hi = (int(x) for x in args.ports.split("-"))
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((args.dev, 0))
    sock.settimeout(0.2)
    f = open(args.out, "wb")
    n = 0
    end = time.time() + args.seconds
    while time.time() < end:
        try:
            frame, addr = sock.recvfrom(262144)
        except socket.timeout:
            continue
        if len(frame) < ETH_HLEN + 20:
            continue
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        off = ETH_HLEN
        if ethertype == 0x8100:
            ethertype = struct.unpack_from("!H", frame, 16)[0]
            off += 4
        if ethertype != 0x0800:
            continue
        ip = frame[off:]
        if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 17:
            continue
        frag = struct.unpack_from("!H", ip, 6)[0]
        if frag & 0x1FFF:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if len(ip) < ihl + 8:
            continue
        sport, dport = struct.unpack_from("!HH", ip, ihl)
        if not (lo <= sport <= hi or lo <= dport <= hi):
            continue
        payload = ip[ihl + 8:]
        if frag & 0x2000:
            payload = payload[:0] + b"\x00" * 0
            frag_flag = 1
        else:
            frag_flag = 0
        direction = 0 if (lo <= dport <= hi) else 1
        ts = time.time_ns()
        f.write(struct.pack("<QIbb", ts, len(payload), direction, frag_flag))
        f.write(payload)
        n += 1
    f.close()
    print(f"captured {n} packets -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
