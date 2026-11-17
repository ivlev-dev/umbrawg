#!/usr/bin/env python3
import socket, sys, time
mode = sys.argv[1]
if mode == "rx":
    port = int(sys.argv[2])
    n = int(sys.argv[3])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("192.168.77.2", port))
    s.settimeout(1.5)
    sizes = []
    while len(sizes) < n:
        try:
            d, _ = s.recvfrom(65535)
            sizes.append(len(d))
        except socket.timeout:
            break
    from collections import Counter
    print("RX_COUNT", len(sizes))
    print("RX_SIZES", sorted(Counter(sizes).items(), key=lambda x: -x[1])[:8])
else:
    port = int(sys.argv[2])
    n = int(sys.argv[3])
    payload = b"x" * 1200
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("10.9.0.1", 0))
    for _ in range(n):
        s.sendto(payload, ("10.9.0.2", port))
        time.sleep(0.0005)
    print("TX_DONE", n)
