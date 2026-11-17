#!/bin/bash
set -u
echo "== lsmod before"
lsmod | grep -Ei 'umbrawg|amneziawg' || true
echo "== insmod umbrawg"
insmod /root/umbrawg/module/src/umbrawg.ko 2>&1 || echo "insmod failed rc=$?"
lsmod | grep -Ei 'umbrawg' || true
echo "== create umbrawg ifaces"
ip link add dev uwgsmoke0 type umbrawg 2>&1 || echo "add failed rc=$?"
ip link set uwgsmoke0 up 2>&1
ip -d link show uwgsmoke0 2>&1 | head -5
echo "== modprobe amneziawg"
modprobe amneziawg 2>&1 || echo "modprobe failed rc=$?"
ip link add dev awgsmoke0 type amneziawg 2>&1 || echo "add failed rc=$?"
ip -d link show awgsmoke0 2>&1 | head -5
echo "== both loaded?"
lsmod | grep -Ei 'umbrawg|amneziawg' || true
echo "== cleanup"
ip link del uwgsmoke0 2>/dev/null
ip link del awgsmoke0 2>/dev/null
echo "== tools binary"
ls -la /root/umbrawg/tools/target/release/ 2>&1 | head -20
echo "== rps support"
ls /sys/class/net/lo/queues/rx-0/rps_cpus 2>&1
echo "== kernel modules"
ls /lib/modules/$(uname -r)/kernel/net/sched/sch_netem.ko.zst 2>&1
echo "== cgroup delegates"
cat /sys/fs/cgroup/cgroup.subtree_control 2>&1
echo "== netns test"
ip netns add smoketest 2>&1 && ip netns del smoketest && echo netns-ok
echo "== perf/bpftrace"
perf --version; bpftrace --version
echo "== sysctl"
cat /proc/sys/net/core/rps_sock_flow_entries
cat /proc/sys/net/ipv4/ip_forward
echo "== done"
