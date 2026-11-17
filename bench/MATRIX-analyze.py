#!/usr/bin/env python3
import csv
import statistics as st
import sys
from collections import defaultdict

path = sys.argv[1] if len(sys.argv) > 1 else '/root/umbrawg/bench/matrix/results.csv'
rows = list(csv.DictReader(open(path)))
ok = [r for r in rows if not r['received_mbps'].startswith('FAIL')]
bad = [r for r in rows if r['received_mbps'].startswith('FAIL')]

g = defaultdict(list)
for r in ok:
    key = (r['module'], int(r['cores']), r['proto'], float(r['target_mbps']),
           float(r['loss_pct']), int(r['obf']), int(r['peers']))
    g[key].append(r)


def med(key, field):
    vals = [float(x[field]) for x in g.get(key, [])]
    return st.median(vals) if vals else None


def n(key):
    return len(g.get(key, []))


def fmt(v):
    return '-' if v is None else f'{v:.1f}'


keys = sorted({(c, p, r, l, o, pe) for (m, c, p, r, l, o, pe) in g})

print(f'rows={len(rows)} ok={len(ok)} fail={len(bad)}')
print()
print('| cores | proto | target | loss% | obf | peers | umbrawg Mbps | amneziawg Mbps | delta % | n |')
print('|---|---|---|---|---|---|---|---|---|---|')
deltas = []
for (c, p, r, l, o, pe) in keys:
    u = med(('umbrawg', c, p, r, l, o, pe), 'received_mbps')
    a = med(('amneziawg', c, p, r, l, o, pe), 'received_mbps')
    if u is None or a is None:
        continue
    d = (u - a) / a * 100 if a else 0
    deltas.append((d, c, p, r, l, o, pe, u, a))
    t = 'max' if r == 0 else f'{r:.0f}'
    print(f'| {c} | {p} | {t} | {l:.0f} | {"on" if o else "off"} | {pe} | {fmt(u)} | {fmt(a)} | {d:+.1f} | {n(("umbrawg", c, p, r, l, o, pe))}/{n(("amneziawg", c, p, r, l, o, pe))} |')

print()
print('== loss/retransmit comparison (target=100, loss>0) ==')
print('| cores | proto | loss% | obf | umbrawg | amneziawg |')
print('|---|---|---|---|---|---|')
for (c, p, r, l, o, pe) in keys:
    if r != 100 or l == 0 or pe != 1:
        continue
    u = g.get(('umbrawg', c, p, r, l, o, pe), [])
    a = g.get(('amneziawg', c, p, r, l, o, pe), [])
    if not u or not a:
        continue
    if p == 'udp':
        uv = st.median([float(x['lost_pct']) for x in u])
        av = st.median([float(x['lost_pct']) for x in a])
        print(f'| {c} | udp | {l:.0f} | {"on" if o else "off"} | {uv:.2f}% lost | {av:.2f}% lost |')
    else:
        uv = st.median([float(x['retransmits']) for x in u])
        av = st.median([float(x['retransmits']) for x in a])
        print(f'| {c} | tcp | {l:.0f} | {"on" if o else "off"} | {uv:.0f} retr | {av:.0f} retr |')

print()
sat = [x for x in deltas if x[3] == 0]
if sat:
    print('== saturation (target=max) ==')
    for d, c, p, r, l, o, pe, u, a in sorted(sat):
        print(f'cores={c} {p} obf={"on" if o else "off"}: umbrawg {u:.0f} vs amneziawg {a:.0f} Mbps ({d:+.1f}%)')
