#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys

UWG = os.environ.get("UWG", "/root/umbrawg/tools/target/debug/uwg")
NS1 = "uwgb1"
NS2 = "uwgb2"
WORK = "/tmp/uwgbench"
OBF_CONF = "/root/umbrawg/bench/obf-params.conf"
PORT_BASE = 51820


def run(args, check=True, stdin=None):
    return subprocess.run(args, check=check, capture_output=True, text=True, input=stdin)


def ip(ns, *args):
    return run(["ip", "-n", ns, *args]).stdout.strip()


def ip_link(ns, *args):
    return run(["ip", "-n", ns, "link", *args]).stdout.strip()


def ip_netns(*args):
    return run(["ip", "netns", *args]).stdout.strip()


def uwg(ns, *args):
    return run(["ip", "netns", "exec", ns, UWG, *args]).stdout.strip()


def genkey():
    return run([UWG, "genkey"]).stdout.strip()


def pubkey(priv):
    return run([UWG, "pubkey"], stdin=priv + "\n").stdout.strip()


def template_params(path):
    params = {}
    section = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("["):
                section = line.strip("[]")
                continue
            if section != "Interface" or "=" not in line:
                continue
            key, val = line.split("=", 1)
            params[key.strip()] = val.strip()
    for drop in ("PrivateKey", "ListenPort", "Table", "MTU"):
        params.pop(drop, None)
    return params


def write_conf(path, iface, peers):
    lines = ["[Interface]"]
    for key, val in iface.items():
        if val is None:
            continue
        lines.append(f"{key} = {val}")
    for peer in peers:
        lines.append("")
        lines.append("[Peer]")
        for key, val in peer.items():
            if val is None:
                continue
            lines.append(f"{key} = {val}")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def teardown():
    for ns in (NS1, NS2):
        run(["ip", "netns", "del", ns], check=False)


def ensure_ns():
    have = run(["ip", "netns", "list"]).stdout
    if f"{NS1}\n" not in have or f"{NS2}\n" not in have:
        teardown()
        ip_netns("add", NS1)
        ip_netns("add", NS2)
        run(["ip", "link", "add", "vwgb1", "type", "veth", "peer", "name", "vwgb2"])
        run(["ip", "link", "set", "vwgb1", "netns", NS1])
        run(["ip", "link", "set", "vwgb2", "netns", NS2])
        ip("uwgb1", "addr", "add", "10.255.0.1/24", "dev", "vwgb1")
        ip("uwgb2", "addr", "add", "10.255.0.2/24", "dev", "vwgb2")
        for a in ("vwgb1", "lo"):
            ip_link(NS1, "set", a, "up")
        for a in ("vwgb2", "lo"):
            ip_link(NS2, "set", a, "up")
        for a in ("vwgb1", "vwgb2"):
            ns = NS1 if a == "vwgb1" else NS2
            run(["ip", "-n", ns, "link", "set", a, "mtu", "1500"], check=False)


def clear_devices(npeers):
    for i in range(32):
        for ns in (NS1, NS2):
            run(["ip", "-n", ns, "link", "del", f"uwg{i}"], check=False)
    for i in range(npeers):
        run(["ip", "-n", NS2, "link", "del", f"uwg{i}"], check=False)
    for i in range(1, 32):
        run(["ip", "-n", NS2, "link", "del", f"uwg{i}"], check=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--peers", type=int, default=1)
    ap.add_argument("--mode", choices=["plain", "obf", "det"], default="plain")
    ap.add_argument("--teardown", action="store_true")
    ap.add_argument("--keep", action="store_true", help="keep existing devices/config")
    args = ap.parse_args()

    if args.teardown:
        teardown()
        return 0

    os.makedirs(WORK, exist_ok=True)
    ensure_ns()
    if not args.keep:
        clear_devices(args.peers)

    n = args.peers
    base = {}
    if args.mode in ("obf", "det"):
        base = template_params(OBF_CONF)
        if "HeaderProtectionKey" in base:
            base["HeaderProtectionKey"] = genkey()
    if args.mode == "det":
        base.update({
            "H1": "712026294", "H2": "1504260570", "H3": "2938347170", "H4": "3916942126",
            "S1": "0", "S2": "0", "S3": "0", "S4": "0",
            "Jc": "0", "Jmin": "0", "Jmax": "0",
            "ContentPaddingAddition": "0-0",
            "RandomTrailers": "off",
            "HeaderProtectionKey": None,
        })
        for k in ("I1", "I2", "I3", "I4", "I5"):
            base.pop(k, None)

    if not args.keep:
        run(["ip", "-n", NS1, "link", "add", "dev", "uwg0", "type", "umbrawg"])

    key_a = genkey()
    pub_a = pubkey(key_a)
    peers_a = []
    env = {"peers": n, "mode": args.mode, "flows": [], "work": WORK}

    for i in range(n):
        if i == 0:
            dev = "uwg0"
        else:
            dev = "uwg0"
        dev_b = f"uwg{i}"
        port_b = PORT_BASE + i
        key_b = genkey()
        pub_b = pubkey(key_b)

        peers_a.append({
            "PublicKey": pub_b,
            "AllowedIPs": f"10.0.{i}.0/24",
            "Endpoint": f"10.255.0.2:{port_b}",
        })

        iface_b = {"PrivateKey": key_b, "ListenPort": str(port_b)}
        iface_b.update(base)
        conf_b = os.path.join(WORK, f"b{i}.conf")
        write_conf(conf_b, iface_b, [{
            "PublicKey": pub_a,
            "AllowedIPs": f"10.9.{i}.1/32",
            "Endpoint": f"10.255.0.1:{PORT_BASE}",
        }])

        if not args.keep:
            run(["ip", "-n", NS2, "link", "add", "dev", dev_b, "type", "umbrawg"])
        ip(NS2, "addr", "add", f"10.0.{i}.2/24", "dev", dev_b)
        uwg(NS2, "setconf", dev_b, conf_b)
        ip_link(NS2, "set", dev_b, "up")
        ip(NS2, "route", "add", f"10.9.{i}.0/24", "dev", dev_b)

        ip(NS1, "addr", "add", f"10.9.{i}.1/32", "dev", "uwg0")

        env["flows"].append({
            "index": i,
            "dev_b": dev_b,
            "port_b": port_b,
            "ip_a": f"10.9.{i}.1",
            "ip_b": f"10.0.{i}.2",
        })

    iface_a = {"PrivateKey": key_a, "ListenPort": str(PORT_BASE)}
    iface_a.update(base)
    conf_a = os.path.join(WORK, "a.conf")
    write_conf(conf_a, iface_a, peers_a)

    uwg(NS1, "setconf", "uwg0", conf_a)
    ip_link(NS1, "set", "uwg0", "up")
    for i in range(n):
        ip(NS1, "route", "add", f"10.0.{i}.0/24", "dev", "uwg0", "src", f"10.9.{i}.1")

    with open(os.path.join(WORK, "env.json"), "w") as f:
        json.dump(env, f, indent=2)
    print(json.dumps(env, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
