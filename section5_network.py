"""
section5_network.py -- Evaluation plan, Section 5 (part 2): AG-to-quorum transfer and total round delay
========================================================================================================

ESTIMATES, NOT NETWORK MEASUREMENTS. This script combines the MEASURED stage
times and the MEASURED message sizes from Section 1 (e2e_results/e2e_summary.csv)
with an explicit, stated network model, and writes the total round delay for
the declared parallelism. It does not emulate a network.

Declared parallelism
  n meters run Report concurrently; the k+1 certifiers run CertShare
  concurrently; every party has its own processor of the measured speed
  (Apple M4). The compute part of each stage is the measured median of the
  slowest party (max over meters / certifiers, as in Section 1).

Network model (all links full duplex)
  B_ag  bandwidth of the AG's link (shared by everything the AG sends or receives)
  B_m   bandwidth of each meter's own access link (meters and certifiers alike;
        certifiers are meters of the quorum)
  RTT   round-trip time between any two parties; each message stage costs RTT/2
  A stage in which many parties send to / receive from the AG is limited by
  the slower of the shared AG link and one party's own link:
    upload        RTT/2 + max(n*|R| / B_ag,       |R| / B_m)
    distribution  RTT/2 + max((k+1)*|T_msg| / B_ag, |T_msg| / B_m)
    shares        RTT/2 + max((k+1)*|theta| / B_ag, |theta| / B_m)
    Gamma to DC   RTT/2 + |Gamma| / B_ag      (AG-DC backhaul)
    Omega publish RTT/2 + |Omega| / B_ag
  Two variants are written: 'ideal' (above) and 'with_setup', which adds 2 RTT
  per message stage for connection set-up (1 RTT TCP + 1 RTT TLS 1.3).
  Not modelled: TCP slow start, loss/retransmission, protocol headers,
  queueing, pipelining of transfer with computation.

Scenarios (default)
  symmetric     B_ag = B_m in {10, 100} Mbps          (as in Section 1)
  asymmetric    B_ag in {100, 1000} Mbps, B_m in {1, 10} Mbps
  RTT in {10, 50, 100} ms

Reporting intervals compared against (cited, not a 'real-time' claim)
  5 min   NEM five-minute settlement: meters record and provide 5-minute
          interval energy data (AEMO, Five-Minute Settlement metering changes)
  15, 30 min  other NEM12 interval configurations (AEMO, same source)
  The comparison asks whether one aggregation round completes within one
  interval, so an aggregate can be produced for every interval.

Usage
  python3 section5_network.py                                   # defaults
  python3 section5_network.py --e2e-dir results/e2e_results --figure-n 1000 250
  python3 section5_network.py --bag 1000 --bm 1 10 --rtt 20 80   # other assumptions

Outputs (in --out, default s5_results)
  s5_network.csv      per (n, scenario, RTT): every stage (measured / estimated),
                      totals ideal and with set-up, network share, margin per interval
  fig_A_round_<n>.png Figure A: critical path by stage for representative n;
                      measured compute in colour, estimated network hatched grey
"""

import argparse
import csv
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

GAMMA_B, OMEGA_B = 100, 296            # Section 2 wire sizes (L = 16)
SETUP_RTTS = 2                          # TCP + TLS 1.3 handshakes per message stage
INTERVALS = {5: 'NEM 5-min trading interval', 15: '15-min interval', 30: '30-min interval'}

COMPUTE = [('report', 'report_single_max_ms'), ('build', 'build_ms'),
           ('goodtrans', 'certshare_max_ms'), ('certcombine', 'certcombine_ms'),
           ('dc', 'dc_ms'), ('verify', 'verify_ms')]
ORDER = ['report', 'net_upload', 'build', 'net_dist', 'goodtrans', 'net_shares',
         'certcombine', 'net_gamma', 'dc', 'net_omega', 'verify']

# colour = job: three validated categorical slots for compute, neutral grey for network
COL = {'goodtrans': '#2a78d6', 'certcombine': '#eb6834', 'other': '#1baf7a', 'net': '#bdbcb6'}
INK, INK2, GRID = '#0b0b0b', '#52514e', '#e4e3df'


def tx_ms(nbytes, mbps):
    return nbytes * 8 / (mbps * 1e6) * 1000.0


def model(row, n, k, bag, bm, rtt):
    one = rtt / 2.0
    R, T, th = float(row['report_B_median']), float(row['dist_msg_B_median']), float(row['share_B_median'])
    st = {name: float(row[col + '_median']) for name, col in COMPUTE}
    st['net_upload'] = one + max(tx_ms(n * R, bag), tx_ms(R, bm))
    st['net_dist'] = one + max(tx_ms((k + 1) * T, bag), tx_ms(T, bm))
    st['net_shares'] = one + max(tx_ms((k + 1) * th, bag), tx_ms(th, bm))
    st['net_gamma'] = one + tx_ms(GAMMA_B, bag)
    st['net_omega'] = one + tx_ms(OMEGA_B, bag)
    return st


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument('--e2e-dir', default='e2e_results')
    ap.add_argument('--out', default='s5_results')
    ap.add_argument('--sym', type=float, nargs='+', default=[10, 100], help='symmetric B_ag = B_m (Mbps)')
    ap.add_argument('--bag', type=float, nargs='+', default=[100, 1000], help='asymmetric: AG link (Mbps)')
    ap.add_argument('--bm', type=float, nargs='+', default=[1, 10], help='asymmetric: meter link (Mbps)')
    ap.add_argument('--rtt', type=float, nargs='+', default=[10, 50, 100], help='RTT (ms)')
    ap.add_argument('--figure-n', type=int, nargs='+', default=[1000], help='representative n for Figure A')
    ap.add_argument('--figure-rtt', type=float, default=50)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    rows = sorted(csv.DictReader(open(os.path.join(a.e2e_dir, 'e2e_summary.csv'))), key=lambda r: int(r['n']))
    scen = [('symmetric', b, b) for b in a.sym] + [('asymmetric', bg, bm) for bg in a.bag for bm in a.bm]

    out, by_n = [], {}
    for r in rows:
        n, k = int(r['n']), int(r['k'])
        comp = {name: float(r[col + '_median']) for name, col in COMPUTE}
        base = {'n': n, 'k': k, 'scenario': 'compute only (zero network)', 'B_ag_mbps': '', 'B_m_mbps': '',
                'rtt_ms': 0}
        base.update({f'{s}_ms': comp.get(s, 0.0) for s in ORDER})
        base['compute_ms'] = sum(comp.values())
        base['total_ideal_ms'] = base['total_with_setup_ms'] = base['compute_ms']
        base['network_share_pct'] = 0.0
        recs = [base]
        for kind, bag, bm in scen:
            for rtt in a.rtt:
                st = model(r, n, k, bag, bm, rtt)
                net = sum(v for s, v in st.items() if s.startswith('net_'))
                rec = {'n': n, 'k': k, 'scenario': f'{kind} AG {bag:g} / meter {bm:g} Mbps',
                       'B_ag_mbps': bag, 'B_m_mbps': bm, 'rtt_ms': rtt}
                rec.update({f'{s}_ms': st[s] for s in ORDER})
                rec['compute_ms'] = sum(comp.values())
                rec['total_ideal_ms'] = rec['compute_ms'] + net
                rec['total_with_setup_ms'] = rec['total_ideal_ms'] + 5 * SETUP_RTTS * rtt
                rec['network_share_pct'] = 100 * net / rec['total_ideal_ms']
                recs.append(rec)
        for rec in recs:
            for m in INTERVALS:
                rec[f'margin_{m}min_x'] = m * 60e3 / rec['total_with_setup_ms']
                rec[f'fits_{m}min'] = rec['total_with_setup_ms'] <= m * 60e3
        out += recs
        by_n[n] = recs

    path = os.path.join(a.out, 's5_network.csv')
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    print(f"wrote {path}")

    for n in sorted(by_n):
        worst = max(by_n[n], key=lambda x: x['total_with_setup_ms'])
        print(f"  n={n:5d}: compute {by_n[n][0]['compute_ms'] / 1e3:6.1f} s | slowest scenario "
              f"'{worst['scenario']}', RTT {worst['rtt_ms']:g} ms: {worst['total_with_setup_ms'] / 1e3:6.1f} s "
              f"(network {worst['network_share_pct']:.0f}%) | 5-min margin x{worst['margin_5min_x']:.1f}")

    for n in a.figure_n:
        if n in by_n:
            figure_a(by_n[n], n, a.figure_rtt, a.out)


def figure_a(recs, n, rtt, out_dir):
    pick = [recs[0]] + [r for r in recs[1:] if r['rtt_ms'] == rtt]
    pick = sorted(pick, key=lambda r: r['total_ideal_ms'])
    labels = []
    for r in pick:
        if r['rtt_ms'] == 0:
            labels.append('Compute only\n(zero network)')
        else:
            labels.append(f"AG {r['B_ag_mbps']:g} Mbps, meters {r['B_m_mbps']:g} Mbps")
    plt.rcParams.update({'font.size': 9, 'axes.edgecolor': INK2, 'xtick.color': INK2, 'ytick.color': INK,
                         'axes.spines.top': False, 'axes.spines.right': False})
    fig, ax = plt.subplots(figsize=(7.4, 0.55 * len(pick) + 1.6))
    ax.grid(axis='x', color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    seen = set()
    for y, r in enumerate(pick):
        left = 0.0
        for s in ORDER:
            v = r[f'{s}_ms'] / 1e3
            if v <= 0:
                continue
            if s.startswith('net_'):
                key, kw = 'net', dict(color=COL['net'], hatch='////', edgecolor='white')
                lab = 'Network transfer (estimated)'
            elif s in ('goodtrans', 'certcombine'):
                key, kw = s, dict(color=COL[s], edgecolor='white')
                lab = {'goodtrans': 'GoodTrans + BLS share (measured)',
                       'certcombine': 'CertCombine (measured)'}[s]
            else:
                key, kw = 'other', dict(color=COL['other'], edgecolor='white')
                lab = 'Report, Build, DC, Verify (measured)'
            ax.barh(y, v, left=left, height=0.55, linewidth=1.5,
                    label=lab if key not in seen else None, **kw)
            seen.add(key)
            left += v
        ax.annotate(f"{left:.1f} s", (left, y), xytext=(4, 0), textcoords='offset points',
                    va='center', fontsize=8.5, color=INK)
    xmax = max(r['total_ideal_ms'] for r in pick) / 1e3
    ax.set_yticks(range(len(pick)))
    ax.set_yticklabels(labels)
    ax.set_xlabel(f'Round delay (s), declared parallelism; network estimated at RTT {rtt:g} ms')
    ax.set_xlim(0, xmax * 1.22)
    if xmax * 1.22 >= 300:
        ax.axvline(300, color=INK2, lw=1, ls=(0, (4, 3)))
        ax.annotate('5-min NEM interval', (300, len(pick) - 0.5), xytext=(-4, 0), textcoords='offset points',
                    ha='right', va='center', fontsize=8, color=INK2)
    ax.set_title(f'Figure A: complete round, critical path by stage (n = {n}, k = {pick[0]["k"]})',
                 loc='left', fontsize=9.5, color=INK)
    ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.32 if len(pick) > 3 else -0.45), ncol=2,
              frameon=False, fontsize=8)
    path = os.path.join(out_dir, f'fig_A_round_{n}.png')
    fig.savefig(path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close(fig)
    print(f"wrote {path}")


if __name__ == '__main__':
    main()