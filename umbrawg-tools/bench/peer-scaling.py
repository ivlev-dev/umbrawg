#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
REPO_ROOT = BENCH_DIR.parent
WORKSPACE_ROOT = Path(os.environ.get("WORKSPACE_ROOT") or REPO_ROOT.parent)


def first_existing_dir(*candidates: Path) -> str:
    for path in candidates:
        if path.is_dir():
            return str(path)
    return str(candidates[0])


def first_existing_file(*candidates: Path) -> str:
    for path in candidates:
        if path.is_file():
            return str(path)
    return str(candidates[0])


def env_path(name: str) -> str:
    return os.environ.get(name, "")


RUSTDIR = first_existing_dir(WORKSPACE_ROOT / "umbrawg-rs",
                             WORKSPACE_ROOT / "rust")
MODDIR = first_existing_dir(
    WORKSPACE_ROOT / "umbrawg-linux-kernel-module" / "src",
    WORKSPACE_ROOT / "module" / "src")
UWG = env_path("UWG") or first_existing_file(
    REPO_ROOT / "target" / "release" / "uwg",
    WORKSPACE_ROOT / "umbrawg-tools" / "target" / "release" / "uwg",
    WORKSPACE_ROOT / "tools" / "target" / "release" / "uwg")
DAEMON = env_path("DAEMON") or first_existing_file(
    Path(RUSTDIR) / "target" / "release" / "umbrawg",
    Path(RUSTDIR) / "umbrawg")
GO_BIN = env_path("GO_BASELINE") or first_existing_file(
    Path("/opt/baseline/amneziawg-go"),
    Path("/usr/local/bin/amneziawg-go"),
    Path("/usr/bin/amneziawg-go"))
AWG = env_path("AWG") or first_existing_file(
    Path("/usr/bin/awg"), Path("/usr/local/bin/awg"))
OBF_CONF = env_path("OBF") or str(BENCH_DIR / "obf-params.conf")
DEFAULT_KO = str(Path(MODDIR) / "umbrawg.ko")
DEFAULT_OUT = str(BENCH_DIR / "results" / "peer-scaling.csv")

NS0, NS1 = "bn0", "bn1"
V0, V1 = "bveth0", "bveth1"
CLI_IFS = ["uwgp0", "uwgp1", "uwgp2", "uwgp3"]
SRV_IFS = ["uwgq0", "uwgq1", "uwgq2", "uwgq3"]
DAEMON_PIDS: list[subprocess.Popen[str]] = []
CLI_PORT0 = 51820
SRV_PORT0 = 51920
UNDERLAY_MTU = 9000
TUN_MTU = 1420
NPROC = os.cpu_count() or 6
MAX_PEERS = 4


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def run(cmd: list[str], check: bool = True,
        input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=check, capture_output=True, text=True,
                          input=input_text)


def ns(name: str, *cmd: str,
       check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["ip", "netns", "exec", name, *cmd], check=check)


def ipn(name: str, *cmd: str,
        check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["ip", "-n", name, *cmd], check=check)


def cleanup() -> None:
    for pid in DAEMON_PIDS:
        try:
            pid.terminate()
        except OSError:
            pass
    for pid in DAEMON_PIDS:
        try:
            pid.wait(timeout=3)
        except Exception:
            try:
                pid.kill()
            except OSError:
                pass
    DAEMON_PIDS.clear()
    run(["bash", "-c", "pkill -f 'iperf3 -s' >/dev/null 2>&1; true"],
        check=False)
    time.sleep(0.5)
    for _ in range(6):
        if os.path.exists("/var/run/netns/" + NS0) or \
                os.path.exists("/var/run/netns/" + NS1):
            run(["ip", "-all", "netns", "delete"], check=False)
            time.sleep(0.5)
        run(["rmmod", "umbrawg"], check=False)
        time.sleep(0.3)
        if not os.path.exists("/var/run/netns/" + NS0) and \
                not os.path.exists("/sys/module/umbrawg"):
            break
    run(["bash", "-c", "echo %x > /sys/devices/virtual/workqueue/cpumask"
         % ((1 << NPROC) - 1)], check=False)


def genkey() -> str:
    return run([UWG, "genkey"]).stdout.strip()


def pubkey(priv: str) -> str:
    return run([UWG, "pubkey"], input_text=priv + "\n").stdout.strip()


def setup_topology() -> None:
    run(["ip", "netns", "add", NS0])
    run(["ip", "netns", "add", NS1])
    run(["ip", "link", "add", V0, "type", "veth", "peer", "name", V1,
         "numtxqueues", str(NPROC), "numrxqueues", str(NPROC)])
    run(["ip", "link", "set", V0, "netns", NS0])
    run(["ip", "link", "set", V1, "netns", NS1])
    for netns, dev, addr in ((NS0, V0, "192.168.77.1/24"),
                             (NS1, V1, "192.168.77.2/24")):
        ipn(netns, "link", "set", dev, "mtu", str(UNDERLAY_MTU))
        ipn(netns, "addr", "add", addr, "dev", dev)
        ipn(netns, "link", "set", dev, "up")
        ipn(netns, "link", "set", "lo", "up")
        ns(netns, "ethtool", "-L", dev, "rx", str(NPROC), "tx", str(NPROC),
           check=False)


def wait_sock(dirs: list[str], names: list[str],
              timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if all(os.path.exists(os.path.join(d, n + ".sock"))
               for d in dirs for n in names):
            return True
        time.sleep(0.2)
    return False


def spawn_daemon(netns: str, iface: str, impl: str, rx_sched: str,
                 cpus: str, daemon: str, go_bin: str) -> None:
    run(["mkdir", "-p", "/var/run/umbrawg", "/var/run/amneziawg"],
        check=False)
    if impl in ("rust", "rust-par"):
        env_list = ["env", "UMBRAWG_THREADS=3",
                    "UMBRAWG_PARALLEL_RX=%d" % (1 if impl == "rust-par" else 0)]
        if impl == "rust-par":
            env_list.append("UMBRAWG_RX_SCHED=" + rx_sched)
        cmd = ["ip", "netns", "exec", netns, "taskset", "-c", cpus,
               *env_list, daemon, "--foreground", iface]
    elif impl == "go":
        cmd = ["ip", "netns", "exec", netns, "taskset", "-c", cpus,
               "env", "GOMAXPROCS=3", go_bin, iface]
    else:
        raise ValueError("unknown impl " + impl)
    DAEMON_PIDS.append(subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))


def start_impl(impl: str, ko: str, single_server: bool, rx_sched: str,
               cpus: str, daemon: str, go_bin: str) -> None:
    srv_ifs = SRV_IFS[:1] if single_server else SRV_IFS
    if impl == "kernel":
        run(["modprobe", "udp_tunnel"], check=False)
        run(["modprobe", "ip6_udp_tunnel"], check=False)
        run(["insmod", ko])
        for dev in CLI_IFS:
            ipn(NS0, "link", "add", dev, "type", "umbrawg")
        for dev in srv_ifs:
            ipn(NS1, "link", "add", dev, "type", "umbrawg")
        return
    for dev in CLI_IFS:
        spawn_daemon(NS0, dev, impl, rx_sched, cpus, daemon, go_bin)
    for dev in srv_ifs:
        spawn_daemon(NS1, dev, impl, rx_sched, cpus, daemon, go_bin)
    sock_dir = ("/var/run/umbrawg" if impl != "go" else "/var/run/amneziawg")
    if not wait_sock([sock_dir], list(CLI_IFS) + list(srv_ifs)):
        log("SOCKET_TIMEOUT impl=%s" % impl)


def obf_block(path: str) -> str:
    if not path or not os.path.exists(path):
        return ""
    skip = ("PrivateKey", "ListenPort", "PublicKey", "AllowedIPs",
            "Endpoint", "PersistentKeepalive")
    out = []
    with open(path) as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith("["):
                continue
            if s.split("=")[0].strip() in skip:
                continue
            out.append(s)
    return "\n".join(out)


def iface_lines(priv: str, port: int, obf: str) -> list[str]:
    lines = ["[Interface]", "PrivateKey = %s" % priv, "ListenPort = %d" % port]
    if obf:
        lines.append(obf)
    return lines


def peer_lines(pub: str, allowed: str, endpoint: str) -> list[str]:
    return ["", "[Peer]", "PublicKey = %s" % pub, "AllowedIPs = %s" % allowed,
            "Endpoint = %s" % endpoint]


def write_confs(obf_conf: str,
                single_server: bool) -> tuple[list[str], list[tuple[str, str, list[int]]]]:
    ck = [genkey() for _ in range(MAX_PEERS)]
    sk = [genkey() for _ in range(MAX_PEERS)]
    cp = [pubkey(k) for k in ck]
    sp = [pubkey(k) for k in sk]
    obf = obf_block(obf_conf)
    client = []
    for i in range(MAX_PEERS):
        port = SRV_PORT0 if single_server else SRV_PORT0 + i
        lines = iface_lines(ck[i], CLI_PORT0 + i, obf)
        lines += peer_lines(sp[0] if single_server else sp[i],
                            "10.9.%d.0/24" % (i + 1),
                            "192.168.77.2:%d" % port)
        path = "/tmp/psc-c%d.conf" % i
        with open(path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        client.append(path)
    server = []
    if single_server:
        lines = iface_lines(sk[0], SRV_PORT0, obf)
        for i in range(MAX_PEERS):
            lines += peer_lines(cp[i], "10.9.%d.0/24" % (i + 1),
                                "192.168.77.1:%d" % (CLI_PORT0 + i))
        path = "/tmp/psc-s0.conf"
        with open(path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        server.append((SRV_IFS[0], path, list(range(1, MAX_PEERS + 1))))
    else:
        for i in range(MAX_PEERS):
            lines = iface_lines(sk[i], SRV_PORT0 + i, obf)
            lines += peer_lines(cp[i], "10.9.%d.0/24" % (i + 1),
                                "192.168.77.1:%d" % (CLI_PORT0 + i))
            path = "/tmp/psc-s%d.conf" % i
            with open(path, "w") as fh:
                fh.write("\n".join(lines) + "\n")
            server.append((SRV_IFS[i], path, [i + 1]))
    return client, server


def apply_configs(client: list[str],
                  server: list[tuple[str, str, list[int]]],
                  tool: str) -> None:
    for i, path in enumerate(client):
        ns(NS0, tool, "setconf", CLI_IFS[i], path)
        ipn(NS0, "addr", "add", "10.9.%d.1/24" % (i + 1), "dev", CLI_IFS[i])
        ipn(NS0, "link", "set", CLI_IFS[i], "mtu", str(TUN_MTU))
        ipn(NS0, "link", "set", CLI_IFS[i], "up")
    for dev, path, idxs in server:
        ns(NS1, tool, "setconf", dev, path)
        for i in idxs:
            ipn(NS1, "addr", "add", "10.9.%d.2/24" % i, "dev", dev)
        ipn(NS1, "link", "set", dev, "mtu", str(TUN_MTU))
        ipn(NS1, "link", "set", dev, "up")


def wait_tunnel(peers: int) -> bool:
    for _ in range(60):
        ok = True
        for i in range(peers):
            r = ns(NS0, "ping", "-c", "1", "-W", "1", "10.9.%d.2" % (i + 1),
                   check=False)
            if r.returncode != 0:
                ok = False
                break
        if ok:
            return True
        time.sleep(0.5)
    return False


def start_servers(peers: int, cpus: str) -> list[subprocess.Popen[bytes]]:
    procs = []
    for i in range(peers):
        procs.append(subprocess.Popen(
            ["ip", "netns", "exec", NS1, "taskset", "-c", cpus,
             "iperf3", "-s", "-B", "10.9.%d.2" % (i + 1),
             "-p", str(5200 + i)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(0.5)
    return procs


def _pids() -> dict[int, tuple[str, int]]:
    out: dict[int, tuple[str, int]] = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % entry) as fh:
                parts = fh.read().rsplit(")", 1)
            comm = parts[0].split("(", 1)[1]
            fields = parts[1].split()
            out[int(entry)] = (comm, int(fields[11]) + int(fields[12]))
        except (OSError, IndexError, ValueError):
            continue
    return out


def _cpu_snapshot() -> dict[str, tuple[int, int]]:
    total: dict[str, tuple[int, int]] = {}
    with open("/proc/stat") as fh:
        for line in fh:
            if not line.startswith("cpu"):
                continue
            f = line.split()
            if not f[0][3:].isdigit():
                continue
            vals = [int(x) for x in f[1:9]]
            total[f[0]] = (sum(vals), vals[3] + vals[4])
    return total


def cpu_summary(before: dict[str, tuple[int, int]],
                after: dict[str, tuple[int, int]]) -> dict[str, float]:
    res: dict[str, float] = {}
    for name, (tot, idle) in after.items():
        if name not in before:
            continue
        btot, bidle = before[name]
        dt = tot - btot
        di = idle - bidle
        res[name] = 0.0 if dt <= 0 else 100.0 * (dt - di) / dt
    return res


def client_counts(peers: int, conns: int) -> list[int]:
    base = conns // peers
    rest = conns % peers
    return [base + (1 if i < rest else 0) for i in range(peers)]


def run_test(peers: int, conns: int, proto: str, duration: int,
             rate_bits: int,
             client_cpus: str) -> tuple[float, int, float]:
    counts = client_counts(peers, conns)
    pins = client_cpus.split(",")
    tasks = []
    for idx in range(peers):
        cmd = ["ip", "netns", "exec", NS0,
               "taskset", "-c", pins[idx % len(pins)],
               "iperf3", "-c", "10.9.%d.2" % (idx + 1),
               "-p", str(5200 + idx),
               "-B", "10.9.%d.1" % (idx + 1), "-t", str(duration),
               "-P", str(max(counts[idx], 1)), "-J"]
        if proto == "tcp":
            cmd += ["-l", "1420"]
        elif rate_bits:
            per = max(rate_bits // peers // max(counts[idx], 1), 1000)
            cmd += ["-u", "-b", str(per), "-l", "1340"]
        else:
            cmd += ["-u", "-b", "0", "-l", "1340"]
        tasks.append(subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True))

    total_mbit = 0.0
    retrans = 0
    sent_pkts = 0
    recv_pkts = 0
    for proc in tasks:
        out, _ = proc.communicate()
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            continue
        end = data["end"]
        recv = end["sum_received"]
        sent = end["sum_sent"]
        total_mbit += float(recv["bits_per_second"]) / 1e6
        retrans += int(sent.get("retransmits", 0) or 0)
        sent_pkts += int(sent.get("packets", 0) or 0)
        recv_pkts += int(recv.get("packets", 0) or 0)
    lost = 0.0
    if proto == "udp" and sent_pkts:
        lost = 100.0 * (sent_pkts - recv_pkts) / sent_pkts
    return round(total_mbit, 1), retrans, round(lost, 3)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Масштабирование UmbraWG по числу пиров: 1/2/4 пары "
                    "устройство-пир (по 4 сокета на пир); режим "
                    "--single-server кладёт 4 пира на одно устройство. "
                    "Требует root, 4 пары, iperf3, собранный umbrawg.ko.")
    ap.add_argument("--ko", default=DEFAULT_KO,
                    help="путь к umbrawg.ko (по умолчанию %s)" % DEFAULT_KO)
    ap.add_argument("--impl", default="kernel",
                    choices=["kernel", "rust", "rust-par", "go"])
    ap.add_argument("--rx-sched", default="peer")
    ap.add_argument("--daemon", default=DAEMON,
                    help="userspace-демон (по умолчанию %s)" % DAEMON)
    ap.add_argument("--go-bin", default=GO_BIN)
    ap.add_argument("--awg", default=AWG)
    ap.add_argument("--variant", default="",
                    help="метка варианта в CSV, обязательна")
    ap.add_argument("--mode", default="3c")
    ap.add_argument("--peers-list", default="1 2 4")
    ap.add_argument("--obf-list", default="0 1")
    ap.add_argument("--obf-conf", default=OBF_CONF,
                    help="профиль обфускации (по умолчанию %s)" % OBF_CONF)
    ap.add_argument("--conns", type=int, default=10)
    ap.add_argument("--duration", type=int, default=8)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--rate", default="1G")
    ap.add_argument("--protos", default="tcp udp")
    ap.add_argument("--single-server", action="store_true",
                    help="4 пира на одном устройстве/сокете сервера")
    ap.add_argument("--client-cpus", default="3,4,5")
    ap.add_argument("--server-cpus", default="3,4,5")
    ap.add_argument("--out", default=DEFAULT_OUT,
                    help="CSV результатов (по умолчанию %s)" % DEFAULT_OUT)
    ap.add_argument("--print-defaults", action="store_true",
                    help="напечатать разрешённые пути и выйти")
    return ap


def print_defaults() -> None:
    values = {
        "BENCH_DIR": str(BENCH_DIR),
        "REPO_ROOT": str(REPO_ROOT),
        "WORKSPACE_ROOT": str(WORKSPACE_ROOT),
        "RUSTDIR": RUSTDIR,
        "MODDIR": MODDIR,
        "UWG": UWG,
        "DAEMON": DAEMON,
        "GO_BIN": GO_BIN,
        "AWG": AWG,
        "OBF": OBF_CONF,
        "KO": DEFAULT_KO,
        "OUT": DEFAULT_OUT,
    }
    for key in sorted(values):
        print("%s=%s" % (key, values[key]))


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if args.print_defaults:
        print_defaults()
        return 0
    if not args.variant:
        ap.error("--variant обязателен")
    if os.geteuid() != 0:
        print("нужен root: netns, insmod, iperf3", file=sys.stderr)
        return 5

    peer_sets = [int(p) for p in args.peers_list.split()]
    if not peer_sets or max(peer_sets) > MAX_PEERS:
        print("--peers-list: допустимо 1..%d" % MAX_PEERS, file=sys.stderr)
        return 2
    if args.impl == "kernel" and not os.path.isfile(args.ko):
        print("нет модуля: %s" % args.ko, file=sys.stderr)
        return 5

    rate_bits = 1000000000 if args.rate not in ("0", "unlimited") else 0
    tunnel_cpus = "0,1,2" if args.mode == "3c" else "0"
    mask_hex = "%x" % sum(1 << int(c) for c in tunnel_cpus.split(","))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    new = not out_path.exists()
    fh = out_path.open("a")
    if new:
        fh.write("variant,mode,obf,peers,conns,proto,rep,mbit,retrans,"
                 "lost_percent,cpu_total,hot_cpus,top_threads,per_cpu\n")
        fh.flush()

    cleanup()
    with open("/sys/devices/virtual/workqueue/cpumask", "w") as wq:
        wq.write(mask_hex + "\n")

    tool = args.awg if args.impl == "go" else UWG
    for obf in args.obf_list.split():
        try:
            setup_topology()
            start_impl(args.impl, args.ko, args.single_server, args.rx_sched,
                       tunnel_cpus, args.daemon, args.go_bin)
            client, server = write_confs(args.obf_conf if obf == "1" else "",
                                         args.single_server)
            apply_configs(client, server, tool)
            if not wait_tunnel(max(peer_sets)):
                log("TUNNEL_FAILED obf=%s" % obf)
                continue
            servers = start_servers(max(peer_sets), args.server_cpus)
            for peers in peer_sets:
                for rep in range(1, args.rounds + 1):
                    for proto in args.protos.split():
                        tbefore = time.time()
                        cpu_before = _cpu_snapshot()
                        pid_before = _pids()
                        try:
                            mbit, retrans, lost = run_test(
                                peers, args.conns, proto, args.duration,
                                rate_bits, args.client_cpus)
                        except subprocess.CalledProcessError as exc:
                            log("IPERF_FAILED peers=%d proto=%s: %s"
                                % (peers, proto, exc))
                            continue
                        cpu_after = _cpu_snapshot()
                        pid_after = _pids()
                        cpus = cpu_summary(cpu_before, cpu_after)
                        total = round(cpus.pop("cpu", 0.0), 1)
                        hot = sum(1 for v in cpus.values() if v >= 80)
                        deltas: dict[str, int] = {}
                        for pid, (comm, ticks) in pid_after.items():
                            if pid not in pid_before:
                                continue
                            d = ticks - pid_before[pid][1]
                            if d > 0:
                                deltas[comm] = deltas.get(comm, 0) + d
                        top = sorted(deltas.items(),
                                     key=lambda kv: -kv[1])[:8]
                        hz = os.sysconf("SC_CLK_TCK")
                        wall = max(time.time() - tbefore, 0.001)
                        top_s = "|".join("%s=%.0f%%" % (
                            c, 100.0 * d / hz / wall) for c, d in top)
                        per_cpu = "|".join(
                            "c%s=%.0f" % (k[3:], v) for k, v in
                            sorted(cpus.items(), key=lambda kv: kv[0]))
                        row = ("%s,%s,%s,%d,%d,%s,%d,%.1f,%d,%.3f,%.1f,%d,"
                               "%s,%s" % (
                                   args.variant, args.mode, obf, peers,
                                   args.conns, proto, rep, mbit, retrans,
                                   lost, total, hot, top_s, per_cpu))
                        fh.write(row + "\n")
                        fh.flush()
                        print(row, flush=True)
            for proc in servers:
                proc.terminate()
            time.sleep(0.3)
        finally:
            cleanup()
            time.sleep(1.0)
    fh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
