#!/usr/bin/env python3
import argparse
import json
import os
import socket
import subprocess
import sys
import time

NS1 = "uwgb1"
NS2 = "uwgb2"
WORK = "/tmp/uwgbench"
IPERF_PORT = 5201


def load_env():
    with open(os.path.join(WORK, "env.json")) as f:
        return json.load(f)


def netns_cmd(ns, args):
    return ["ip", "netns", "exec", ns] + args


def wait_port(ip_b, port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for ns in (NS2,):
            r = subprocess.run(["ip", "netns", "exec", ns, "ss", "-ltnH", f"sport = :{port}"],
                               capture_output=True, text=True)
            if r.returncode == 0 and str(port) in r.stdout:
                return True
        time.sleep(0.05)
    return False


def run_rep(env, proto, seconds):
    flows = env["flows"]
    servers = []
    for fl in flows:
        args = ["iperf3", "-s", "-1", "-B", fl["ip_b"], "-p", str(IPERF_PORT)]
        servers.append(subprocess.Popen(netns_cmd(NS2, args),
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(0.5)

    clients = []
    for fl in flows:
        args = ["iperf3", "-J", "-c", fl["ip_b"], "-p", str(IPERF_PORT), "-t", str(seconds), "-O", "1"]
        if proto == "udp":
            args += ["-u", "-b", "0"]
        clients.append(subprocess.Popen(netns_cmd(NS1, args),
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True))

    total = 0.0
    lost = 0.0
    per_flow = []
    for fl, proc in zip(flows, clients):
        out, _ = proc.communicate()
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            data = {"end": {}}
        end = data.get("end", {})
        if proto == "udp":
            rate = end.get("sum", {}).get("bits_per_second", 0.0)
            per_flow.append(rate)
            lost += end.get("sum", {}).get("lost_percent", 0.0)
        else:
            rate = end.get("sum_received", {}).get("bits_per_second")
            if not rate:
                rate = end.get("sum_sent", {}).get("bits_per_second", 0.0)
            per_flow.append(rate)
        total += rate
    for proc in servers:
        proc.wait(timeout=10)
    return {
        "aggregate_gbps": total / 1e9,
        "per_flow_gbps": [r / 1e9 for r in per_flow],
        "udp_lost_percent": lost / max(len(flows), 1) if proto == "udp" else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proto", choices=["tcp", "udp", "both"], default="tcp")
    ap.add_argument("--seconds", type=int, default=5)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--label", default="run")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    env = load_env()
    protos = ["tcp", "udp"] if args.proto == "both" else [args.proto]
    result = {"label": args.label, "peers": env["peers"], "mode": env["mode"], "runs": {}}
    for proto in protos:
        reps = []
        for _ in range(args.reps):
            reps.append(run_rep(env, proto, args.seconds))
            time.sleep(0.3)
        reps_sorted = sorted(reps, key=lambda r: r["aggregate_gbps"])
        rep = reps_sorted[len(reps_sorted) // 2]
        rep["all"] = [r["aggregate_gbps"] for r in reps]
        result["runs"][proto] = rep
    print(json.dumps(result, indent=2))
    if args.out:
        with open(args.out, "w") as f:
            json.dump(result, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
