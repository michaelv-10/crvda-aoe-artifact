"""
section4_scaling.py -- scaling with n, k and L
==========================================================================

Every number comes from the same code paths as the earlier sections: complete
rounds are run with e2e_round.run_round (Report -> Build -> CertShare ->
CertCombine -> AggrDec/DecProve -> Verify, asserting that Verify accepts and
X_t equals the true sum), and sizes / memory with section2_validate (encoded
messages; each role in a fresh process).

Part n  (--part n)   Vary n. NO NEW RUNS: reads the Section 1 results
                     (e2e_results/e2e_summary.csv, e2e_network.csv) and writes
                     the four quantities Section 4 asks to plot:
                       per-certifier verification time  certshare_one_ms
                       parallel end-to-end latency      parallel_compute_bound_ms
                                                        (+ network: parallel_total_ms)
                       aggregate CPU work               total_cpu_ms
                       AG-to-quorum traffic             (k+1) x dist_msg_B
Part k  (--part k)   Vary k: n = 200, k in {0, 20, 40, 60}, L = 16. Complete
                     rounds; reports CertCombine latency, one certifier's
                     GoodTrans (should not depend on k), total certifier CPU
                     work, AG-to-quorum traffic and the parallel bound.
                     k = 0 is the no-collusion setting (a quorum of one) and
                     must not be read as behaviour at nonzero thresholds.
Part L  (--part L)   Plaintext bit length: n = 200, k = 40, L in {8, 16, 32}.
                     First checks that the complete range proof and bounded
                     discrete log WORK at each L (honest round recovers the
                     sum; x = 2^L - 1 accepted; x = 2^L rejected by the range
                     proof even with a valid linking proof and signature),
                     then measures cost (complete rounds) and sizes / memory
                     (fresh-process roles, as in Section 2).
                     Readings: synthetic uniform in [0, 2^L) for every L --
                     costs do not depend on the values, and real readings at
                     3 decimals do not fit L = 8.

Certifiers: with n = 200 one certifier is executed per round and the
certification totals are derived as (k+1) x one (validated in Section 1 to
within 1% for n <= 100); --all-certifiers runs every one (slow).

Usage
  python3 section4_scaling.py --part n                       # seconds, from Section 1 results
  caffeinate -i python3 section4_scaling.py --part k | tee s4k.log      # ~20 min
  caffeinate -i python3 section4_scaling.py --part L | tee s4L.log      # ~25 min
  python3 section4_scaling.py --part k --data readings.xlsx  # k-sweep on the real readings
  python3 section4_scaling.py --smoke                        # quick check of k and L parts

Outputs (in --out, default s4_results; s4_smoke with --smoke)
  s4_n_scaling.csv
  s4_k_trials.csv, s4_k_summary.csv
  s4_L_checks.txt, s4_L_trials.csv, s4_L_summary.csv, L<L>/s2_*.csv (sizes, storage, memory)
"""

import argparse
import csv
import math
import os
import random as pyrandom
import sys
import time

from charm.toolbox.pairinggroup import ZR, G1

import crvda_aoe_v2 as C
import e2e_round as E
import section2_validate as S2
from crvda_wire import Wire

K_SWEEP_N, K_VALUES = 200, (0, 20, 40, 60)
L_SWEEP_N, L_SWEEP_KPCT, L_VALUES = 200, 20, (8, 16, 32)


def q(vals, p):
    return C._quantile(sorted(vals), p)


def write_csv(path, rows):
    keys = []
    for r in rows:
        for k_ in r:
            if k_ not in keys:
                keys.append(k_)
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def summarize(rows, group_key, cols):
    out = []
    for g in sorted({r[group_key] for r in rows}):
        rs = [r for r in rows if r[group_key] == g]
        s = {group_key: g, 'trials': len(rs)}
        for c in cols:
            v = [float(r[c]) for r in rs if r.get(c) not in ('', None)]
            if v:
                s[c + '_median'], s[c + '_q1'], s[c + '_q3'] = q(v, .5), q(v, .25), q(v, .75)
        out.append(s)
    return out


# ---------------------------------------------------------------------------
# Part n
# ---------------------------------------------------------------------------

def part_n(e2e_dir, out_dir):
    summ = list(csv.DictReader(open(os.path.join(e2e_dir, 'e2e_summary.csv'))))
    net = list(csv.DictReader(open(os.path.join(e2e_dir, 'e2e_network.csv'))))
    rows = []
    for s in summ:
        n, k = int(s['n']), int(s['k'])
        r = {'n': n, 'k': k, 'trials': s['trials'], 'certifiers_derived': s['certifiers_derived']}
        for c in ('certshare_one_ms', 'parallel_compute_bound_ms', 'total_cpu_ms'):
            for st in ('median', 'q1', 'q3'):
                r[f'{c}_{st}'] = float(s[f'{c}_{st}'])
        r['agq_traffic_B'] = (k + 1) * float(s['dist_msg_B_median'])
        r['total_sent_B'] = float(s['total_sent_B_median'])
        for nr in net:
            if int(nr['n']) == n:
                tag = f"{float(nr['bandwidth_mbps']):g}Mbps_{float(nr['rtt_ms']):g}ms"
                r[f'parallel_total_ms_{tag}'] = float(nr['parallel_total_ms'])
        rows.append(r)
    write_csv(os.path.join(out_dir, 's4_n_scaling.csv'), rows)
    print("Part n (from Section 1 results):")
    for r in rows:
        print(f"  n={r['n']:5d} k={r['k']:4d}: one certifier {r['certshare_one_ms_median'] / 1000:7.2f} s | "
              f"parallel bound {r['parallel_compute_bound_ms_median'] / 1000:7.2f} s | "
              f"CPU {r['total_cpu_ms_median'] / 3.6e6:6.2f} h | AG->Q {r['agq_traffic_B'] / 1e6:8.2f} MB")
    print(f"Wrote {os.path.join(out_dir, 's4_n_scaling.csv')}")


# ---------------------------------------------------------------------------
# Part k
# ---------------------------------------------------------------------------

K_COLS = ['certcombine_ms', 'certshare_one_ms', 'cert_all_cpu_ms', 'total_cpu_ms',
          'parallel_compute_bound_ms', 'build_ms', 'dc_ms', 'verify_ms', 'report_single_median_ms',
          'agq_traffic_B', 'shares_traffic_B', 'total_sent_B']


def part_k(n, ks, L, trials, data, seed, all_cert, out_dir):
    rng = pyrandom.Random(seed)
    rows = []
    print(f"Part k: n = {n}, k in {list(ks)}, L = {L}, {trials} trials each "
          f"({'all certifiers executed' if all_cert else 'one certifier executed, totals derived'})")
    for k in ks:
        for tr in range(trials):
            xs = (C.get_dataset_values(data, n) if data is not None
                  else [rng.randint(0, 2 ** L - 1) for _ in range(n)])
            t0 = time.perf_counter()
            r = E.run_round(n, k, L, tr, xs, all_cert or k == 0, 'round')
            r['agq_traffic_B'] = (k + 1) * r['dist_msg_B']
            r['shares_traffic_B'] = (k + 1) * r['share_B']
            rows.append(r)
            print(f"  k={k:3d} trial {tr + 1}/{trials}: CertCombine {r['certcombine_ms'] / 1000:6.2f} s, "
                  f"one GoodTrans {r['certshare_one_ms'] / 1000:6.2f} s, "
                  f"AG->Q {r['agq_traffic_B'] / 1e6:6.2f} MB  [{time.perf_counter() - t0:.0f} s]")
        write_csv(os.path.join(out_dir, 's4_k_trials.csv'), rows)
    summ = summarize(rows, 'k', K_COLS)
    meds = [s['certshare_one_ms_median'] for s in summ]
    spread = 100 * (max(meds) - min(meds)) / (sum(meds) / len(meds))
    for s in summ:
        s['n'] = n
        s['goodtrans_spread_across_k_pct'] = spread
    write_csv(os.path.join(out_dir, 's4_k_summary.csv'), summ)
    print("Medians:")
    for s in summ:
        print(f"  k={s['k']:3d}: CertCombine {s['certcombine_ms_median'] / 1000:6.2f} s | one GoodTrans "
              f"{s['certshare_one_ms_median'] / 1000:6.2f} s | all certifiers CPU "
              f"{s['cert_all_cpu_ms_median'] / 1000:8.1f} s | AG->Q {s['agq_traffic_B_median'] / 1e6:6.2f} MB")
    print(f"One certifier's GoodTrans varies by {spread:.1f}% across k (expected: essentially independent of k).")


# ---------------------------------------------------------------------------
# Part L
# ---------------------------------------------------------------------------

def L_checks(L, log):
    """The complete range proof and bounded discrete log must WORK at this L
    before its costs are reported."""
    rng = pyrandom.Random(L)
    log(f"L = {L}:")
    n, k = 6, 1
    xs = [2 ** L - 1] + [rng.randint(0, 2 ** L - 1) for _ in range(n - 1)]   # includes the maximum
    try:
        E.run_round(n, k, L, 0, xs, True, 'round')
        ok = True
    except AssertionError as e:
        ok, msg = False, str(e)
    log.check(ok, f"complete round (incl. a reading of 2^L - 1 = {2 ** L - 1}) verifies and recovers the exact sum"
              + ("" if ok else f": {msg}"))
    try:
        E.run_round(n, k, L, 1, [0] * n, True, 'round')
        ok0 = True
    except AssertionError:
        ok0 = False
    log.check(ok0, "complete round with all readings 0 (lower end of the range) recovers 0")

    sch = C.CRVDA_AOE('BN254')
    sch.setup(n, k, L, sid=f"s4-L{L}".encode())
    G, g1, hx = sch.group, sch.g1, sch.hx
    t = 1
    ell = sch.ell(t)
    A = C.hash_to_g1(G, b'H1', ell)
    B = C.hash_to_g1(G, b'H2', ell)
    try:
        sch.report(1, t, 2 ** L)
        refused = False
    except ValueError:
        refused = True
    log.check(refused, "an honest meter refuses to report x = 2^L")
    big, gam = 2 ** L, G.random(ZR)
    xz = G.init(ZR, big)
    V = (g1 ** xz) * (hx ** gam)
    Ci = (g1 ** xz) * (A ** sch.si[1]) * (B ** sch.ti[1])
    pl = C.link_prove(G, g1, sch.u, sch.h, hx, A, B, [sch.sid, ell, 1], sch.K[1], Ci, V,
                      (xz, sch.si[1], sch.ti[1], sch.rho[1], gam))
    pr = C.range_prove_bp(G, g1, hx, sch.g_vec, sch.h_vec, V, big, gam, L, [b'RANGE-CTX', sch.sid, ell, 1])
    pi_val = (V, pl, pr)
    msg = C.cat(G, b'REP', sch.sid, ell, 1, Ci, pi_val)
    R = (1, ell, Ci, pi_val, C.schnorr_sign(G, g1, sch.rsk[1], msg))
    ok, tm = sch.verify_rep(R, return_timing=True)
    log.check(not ok and tm['range'] > 0,
              "a corrupted meter's x = 2^L with valid linking proof and signature is rejected by the range proof")


L_COLS = ['report_single_median_ms', 'certshare_one_ms', 'certcombine_ms', 'dc_ms', 'verify_ms',
          'bsgs_precompute_ms', 'setup_ms', 'parallel_compute_bound_ms', 'total_cpu_ms', 'report_B',
          'dist_msg_B', 'total_sent_B']


def part_L(n, k_pct, Ls, trials, seed, out_dir):
    k = min(math.ceil(k_pct / 100 * n), n - 2)
    log = S2.Log(os.path.join(out_dir, 's4_L_checks.txt'))
    log(f"Part L: n = {n}, k = {k}, L in {list(Ls)}; readings uniform in [0, 2^L)")
    log("Validity checks (must pass before costs are reported):")
    for L in Ls:
        L_checks(L, log)
    log.save()
    if log.fails:
        print("Validity checks failed; costs not measured.")
        return 1

    rng = pyrandom.Random(seed)
    rows = []
    for L in Ls:
        for tr in range(trials):
            xs = [rng.randint(0, 2 ** L - 1) for _ in range(n)]
            t0 = time.perf_counter()
            r = E.run_round(n, k, L, tr, xs, False, 'round')
            rows.append(r)
            print(f"  L={L:2d} trial {tr + 1}/{trials}: Report {r['report_single_median_ms']:.1f} ms, "
                  f"GoodTrans {r['certshare_one_ms'] / 1000:.2f} s, DC {r['dc_ms']:.1f} ms, "
                  f"table build {r['bsgs_precompute_ms']:.0f} ms  [{time.perf_counter() - t0:.0f} s]")
        write_csv(os.path.join(out_dir, 's4_L_trials.csv'), rows)
    summ = summarize(rows, 'L', L_COLS)

    # sizes, storage and peak memory per L: the Section 2 measurement (fresh-process roles)
    S2.W_SIZE_G1 = Wire(C.CRVDA_AOE('BN254').group).size[G1]
    for s in summ:
        L = s['L']
        d = os.path.join(out_dir, f"L{L}")
        os.makedirs(d, exist_ok=True)
        S2.run_sweep([n], k_pct, L, seed, d, S2.Log(os.path.join(d, 's2_log.txt')))
        sz = next(csv.DictReader(open(os.path.join(d, 's2_sizes.csv'))))
        mem = {m['role']: m for m in csv.DictReader(open(os.path.join(d, 's2_memory.csv')))}
        s.update({'n': n, 'k': k,
                  'wire_report_B': int(sz['report_B']), 'wire_omega_B': int(sz['omega_B']),
                  'wire_total_sent_B': int(sz['total_sent_B']),
                  'certifier_input_MiB': float(mem['certifier']['input_MiB']),
                  'certifier_working_MiB': float(mem['certifier']['working_MiB']),
                  'meter_working_MiB': float(mem['meter']['working_MiB']),
                  'dc_table_entries': int(mem['dc']['table_entries']),
                  'dc_table_MiB': float(mem['dc']['table_MiB']),
                  'dc_working_MiB': float(mem['dc']['working_MiB']),
                  'dc_table_build_s': float(mem['dc']['table_build_s'])})
    write_csv(os.path.join(out_dir, 's4_L_summary.csv'), summ)
    print("Medians:")
    for s in summ:
        print(f"  L={s['L']:2d}: |R| {s['wire_report_B']} B, Report {s['report_single_median_ms_median']:.1f} ms, "
              f"GoodTrans {s['certshare_one_ms_median'] / 1000:.2f} s, DC {s['dc_ms_median']:.1f} ms, "
              f"table {s['dc_table_entries']} entries / {s['dc_table_MiB']:.1f} MiB / "
              f"{s['bsgs_precompute_ms_median'] / 1000:.2f} s, certifier memory "
              f"{s['certifier_input_MiB'] + s['certifier_working_MiB']:.1f} MiB")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument('--part', choices=('n', 'k', 'L', 'all'), default='all')
    ap.add_argument('--e2e-dir', default='e2e_results', help='Section 1 output folder (for --part n)')
    ap.add_argument('--trials', type=int, default=10)
    ap.add_argument('--all-certifiers', action='store_true')
    ap.add_argument('--data', default=None, help='Excel readings for the k-sweep (as e2e_round.py)')
    ap.add_argument('--column', type=int, default=0)
    ap.add_argument('--no-header', action='store_true')
    ap.add_argument('--decimals', type=int, default=3)
    ap.add_argument('--seed', type=int, default=1234)
    ap.add_argument('--smoke', action='store_true')
    ap.add_argument('--out', default=None)
    args = ap.parse_args(argv)

    out_dir = args.out or ('s4_smoke' if args.smoke else 's4_results')
    os.makedirs(out_dir, exist_ok=True)
    kn, ks, ln, trials = K_SWEEP_N, K_VALUES, L_SWEEP_N, args.trials
    if args.smoke:
        kn, ks, ln, trials = 20, (0, 2, 4), 20, 2

    data, L16 = None, 16
    if args.data:
        data, _ = C.load_real_readings(args.data, args.decimals, column=args.column,
                                       has_header=not args.no_header)
        L16 = max(16, C.required_L(max(data)))

    if args.part in ('n', 'all') and not args.smoke:
        if os.path.exists(os.path.join(args.e2e_dir, 'e2e_summary.csv')):
            part_n(args.e2e_dir, out_dir)
        else:
            print(f"Part n skipped: {args.e2e_dir}/e2e_summary.csv not found (use --e2e-dir).")
    if args.part in ('k', 'all'):
        C._warmup('BN254', L16, 1)
        part_k(kn, ks, L16, trials, data, args.seed, args.all_certifiers, out_dir)
    if args.part in ('L', 'all'):
        rc = part_L(ln, L_SWEEP_KPCT, L_VALUES, trials, args.seed, out_dir)
        if rc:
            return rc
    print(f"Done. Results in {out_dir}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())