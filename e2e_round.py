"""
e2e_round.py: end-to-end round latency
=====================================================================

Runs ONE COMPLETE SUCCESSFUL ROUND of CRVDA-AOE per trial -- Report for all n
meters, Build, CertShare (GoodTrans + BLS share), CertCombine, AggrDec,
DecProve and the public Verify(Omega_t) -- for each n in the n-sweep with
k = ceil(20% of n), and records, per stage:

  * wall-clock time (time.perf_counter) and CPU time (time.process_time);
  * the exact number of bytes each message puts on the wire;
  * the concurrency level of each reported total.

Execution model
---------------
Everything runs in ONE Python process on ONE machine, so all n meters and all
k+1 certifiers execute SEQUENTIALLY (concurrency level 1), and messages are
passed in memory (no network). From the measured components the script
derives three totals, each clearly labelled:

  serial_wall_ms ............ MEASURED: one stopwatch around the complete round
                              executed sequentially. Only filled in when every
                              certifier was actually executed (see
                              --all-certifiers-up-to); otherwise left empty.
  serial_wall_est_ms ........ the sum of the stage wall times; when only one
                              certifier was executed, the certification stage is
                              (k+1) x that certifier (DERIVED, flagged in
                              certifiers_derived).
  parallel_compute_bound_ms . ANALYTICAL PARALLEL LOWER BOUND (not a measured
                              end-to-end time): n meters concurrent, k+1
                              certifiers concurrent, one party per machine,
                              ZERO network delay:
                                max_i Report_i + Build + max_j CertShare_j
                                + CertCombine + (AggrDec + DecProve) + Verify
  parallel_total_ms ......... (network file) the bound above PLUS a modelled
                              network delay for a stated bandwidth and RTT
                              (estimate, not a measurement).

total_cpu_ms is the CPU work of ALL parties together (all n reports, Build,
all k+1 certifiers, CertCombine, DC, Verify); the certifier part is derived
when not all certifiers were executed.

Network model
-------------
For each (bandwidth B, round-trip time RTT) the delay of a message stage is
RTT/2 + bits/B on its bottleneck link. Every link has bandwidth B; the AG's
link is shared, so the n uploads and the k+1 transcript copies are serialized
on it. No TCP handshake, slow start, packet loss or protocol header overhead
is modelled. Stages:
  upload    n reports, SM -> AG          RTT/2 + n|R| / B
  dist      k+1 transcripts, AG -> Q     RTT/2 + (k+1)|AG->j| / B
  shares    k+1 shares, Q -> AG          RTT/2 + (k+1)|theta| / B
  ag_dc     Gamma_t, AG -> DC            RTT/2 + |Gamma| / B
  dc_v      Omega_t, DC -> verifier      RTT/2 + |Omega| / B

Byte accounting
---------------
Group elements are counted from the objects actually produced, at the
compressed BN254 sizes used in the draft (G1 32 B, G2 64 B, Zp 32 B, GT 384 B):
the *_B columns. The *_charm_B columns give the same messages at the raw
length of Charm's own serialization of each element, for comparison.
Fixed fields: meter identity i = 2 bytes (uint16); transcript digest = 32
bytes; X_t = fewest bytes holding n(2^L-1) (4 B for L = 16). Round label: with --label round (default) only
the 4-byte round number t is transmitted and every party recomputes
ell_t = ROUND || sid || t || rid from the public sid and rid; with --label full
the full ell_t byte string is counted in every message that carries it.

Usage
  python3 e2e_round.py --smoke                    # tiny check (n = 10, 20; L = 8)
  python3 e2e_round.py                            # full n-sweep, trials as in run_experiments.py
  python3 e2e_round.py --trials 3                 # same trial count for every n
  python3 e2e_round.py --all-certifiers-up-to 250 # execute all k+1 certifiers up to n = 250
  python3 e2e_round.py --bandwidth 10 100 --rtt 10 50 100
  python3 e2e_round.py --data readings.xlsx       # real readings (see run_experiments.py)
  python3 e2e_round.py --resume                   # continue after an interruption
  caffeinate -i python3 e2e_round.py | tee e2e.log    # macOS: keep the Mac awake

Outputs (in --out)
  e2e_trials.csv    one row per (n, trial): every stage, CPU, bytes, totals
  e2e_summary.csv   per n: median, q1, q3 of every numeric column
  e2e_network.csv   per (n, B, RTT): modelled network delay per stage and
                    the parallel bound with network
  e2e_env.txt       environment and the exact definitions above
"""

import argparse
import base64
import csv
import math
import os
import random as pyrandom
import time

import crvda_aoe_v2 as C

N_SWEEP = [50, 100, 250, 500, 750, 1000]
N_TRIALS = {50: 10, 100: 10, 250: 10, 500: 5, 750: 3, 1000: 3}
K_PCT = 20

NOMINAL = {'G1': 32, 'G2': 64, 'ZR': 32, 'GT': 384}     # compressed BN254, as in the draft
ID_BYTES, ROUND_BYTES, DIGEST_BYTES = 2, 4, 32
_TYPE_CODE = {b'0': 'ZR', b'1': 'G1', b'2': 'G2', b'3': 'GT'}   # Charm serialization prefixes


# ---------------------------------------------------------------------------
# byte accounting
# ---------------------------------------------------------------------------

def elem_info(group, e):
    """(type, raw serialized length) of one Charm element, read from Charm's
    own serialization b'<code>:<base64>'."""
    s = group.serialize(e)
    code, sep, b64 = s.partition(b':')
    if not sep or code not in _TYPE_CODE:
        raise ValueError(f"unrecognised Charm serialization prefix {s[:8]!r}; "
                         f"update _TYPE_CODE in e2e_round.py for this Charm version")
    return _TYPE_CODE[code], len(base64.b64decode(b64))


def elem_bytes(group, obj):
    """(nominal bytes, Charm raw bytes, {type: count}) of every group element
    inside obj (tuples, lists and dicts are walked; other values are skipped
    and must be counted explicitly by the caller)."""
    counts, raw = {}, 0
    stack = [obj]
    while stack:
        o = stack.pop()
        if isinstance(o, (bytes, str, int, float, bool)) or o is None:
            continue
        if isinstance(o, (tuple, list)):
            stack.extend(o)
            continue
        if isinstance(o, dict):
            stack.extend(o.values())
            continue
        t, n = elem_info(group, o)
        counts[t] = counts.get(t, 0) + 1
        raw += n
    nominal = sum(NOMINAL[t] * c for t, c in counts.items())
    return nominal, raw, counts


def x_bytes(n, L):
    """Bytes of the published integer X_t: the fewest bytes holding the bound
    n(2^L - 1) (4 bytes for L = 16 up to n = 65,536)."""
    return max(1, math.ceil((n * (2 ** L - 1)).bit_length() / 8))


def label_bytes(ell_t, label_mode):
    return ROUND_BYTES if label_mode == 'round' else len(ell_t)


def message_sizes(sch, ell_t, reports, C_agg, theta, Gamma, Omega, label_mode):
    """Bytes of every message of the round: (nominal, charm) pairs."""
    G = sch.group
    lb = label_bytes(ell_t, label_mode)

    def rep(R):
        i, ell, Ci, pi_val, sigma = R
        nom, raw, _ = elem_bytes(G, (Ci, pi_val, sigma))
        fixed = ID_BYTES + label_bytes(ell, label_mode)
        return fixed + nom, fixed + raw

    rsz = [rep(R) for R in reports]
    report_nom = max(s[0] for s in rsz)              # all reports have the same size
    report_raw = max(s[1] for s in rsz)
    T_nom, T_raw = sum(s[0] for s in rsz), sum(s[1] for s in rsz)

    c_nom, c_raw, _ = elem_bytes(G, C_agg)
    dist_nom = lb + DIGEST_BYTES + c_nom + T_nom        # AG -> one certifier: (t, d, C, T)
    dist_raw = lb + DIGEST_BYTES + c_raw + T_raw

    th_nom, th_raw, _ = elem_bytes(G, theta)

    _, _, _, tau = Gamma
    g_nom, g_raw, _ = elem_bytes(G, (C_agg, tau))
    gamma_nom, gamma_raw = lb + DIGEST_BYTES + g_nom, lb + DIGEST_BYTES + g_raw

    _, Xt, Zt, pi_dec = Omega
    o_nom, o_raw, _ = elem_bytes(G, (Zt, pi_dec))
    xb = x_bytes(sch.n, sch.L)
    omega_nom, omega_raw = gamma_nom + xb + o_nom, gamma_raw + xb + o_raw

    # public roster / registration data: per meter (i, rvk_i, K_i); per quorum
    # member (j, W_j); global (rid, S0, T0, u, h, g1, g2, WQ)
    r_nom, r_raw, _ = elem_bytes(G, ([(sch.rvk[i], sch.K[i]) for i in sch.rvk],
                                     [sch.W[j] for j in sch.Q],
                                     (sch.S0, sch.T0, sch.u, sch.h, sch.g1, sch.g2, sch.WQ)))
    roster_fixed = ID_BYTES * (sch.n + len(sch.Q)) + DIGEST_BYTES
    return {
        'report_B': report_nom, 'report_charm_B': report_raw,
        'transcript_B': T_nom, 'transcript_charm_B': T_raw,
        'dist_msg_B': dist_nom, 'dist_msg_charm_B': dist_raw,
        'share_B': th_nom, 'share_charm_B': th_raw,
        'gamma_B': gamma_nom, 'gamma_charm_B': gamma_raw,
        'omega_B': omega_nom, 'omega_charm_B': omega_raw,
        'roster_B': roster_fixed + r_nom, 'roster_charm_B': roster_fixed + r_raw,
    }


def total_bytes_sent(sz, n, k, suffix='_B'):
    """All bytes put on the wire in one round."""
    return (n * sz['report' + suffix] + (k + 1) * sz['dist_msg' + suffix]
            + (k + 1) * sz['share' + suffix] + sz['gamma' + suffix] + sz['omega' + suffix])


# ---------------------------------------------------------------------------
# network model (estimate, not a measurement)
# ---------------------------------------------------------------------------

def network_ms(sz, n, k, bw_mbps, rtt_ms):
    one_way = rtt_ms / 2.0

    def tx(nbytes):
        return nbytes * 8 / (bw_mbps * 1e6) * 1000.0

    stages = {
        'net_upload_ms': one_way + tx(n * sz['report_B']),
        'net_dist_ms': one_way + tx((k + 1) * sz['dist_msg_B']),
        'net_shares_ms': one_way + tx((k + 1) * sz['share_B']),
        'net_ag_dc_ms': one_way + tx(sz['gamma_B']),
        'net_dc_v_ms': one_way + tx(sz['omega_B']),
    }
    stages['net_total_ms'] = sum(stages.values())
    return stages


# ---------------------------------------------------------------------------
# one complete round
# ---------------------------------------------------------------------------

class Clock:
    """Accumulates wall-clock (perf_counter) and CPU (process_time) time."""

    def __init__(self):
        self.wall = 0.0
        self.cpu = 0.0

    def __enter__(self):
        self._w, self._c = time.perf_counter(), time.process_time()
        return self

    def __exit__(self, *exc):
        self.wall += time.perf_counter() - self._w
        self.cpu += time.process_time() - self._c
        return False


def ms(x):
    return x * 1000.0


def run_round(n, k, L, trial, xs, measure_all_certifiers, label_mode):
    sch = C.CRVDA_AOE('BN254')

    # Setup and the bounded-DLog table are one-time costs: timed, reported
    # separately, excluded from every per-round figure.
    setup_c, bsgs_c = Clock(), Clock()
    with setup_c:
        sch.setup(n, k, L, sid=f"e2e-{n}-{k}-{trial}".encode())
    with bsgs_c:
        sch.build_bsgs()

    t = trial
    ell_t = sch.ell(t)
    round_start = time.perf_counter()

    # (1) every meter's Report, executed one after another
    rep_wall, rep_cpu, reports = [], [], []
    for i in range(1, n + 1):
        c = Clock()
        with c:
            reports.append(sch.report(i, t, xs[i - 1]))
        rep_wall.append(c.wall)
        rep_cpu.append(c.cpu)

    # (2) AG Build
    build_c = Clock()
    with build_c:
        T, C_agg, d = sch.build(t, reports)

    # (3) CertShare = GoodTrans + BLS share, per certifier
    cert_wall, cert_cpu, shares = [], [], {}
    to_run = sch.Q if measure_all_certifiers else sch.Q[:1]
    for j in to_run:
        c = Clock()
        with c:
            shares[j] = sch.cert_share(j, t, T, C_agg, d)
        cert_wall.append(c.wall)
        cert_cpu.append(c.cpu)
    if not measure_all_certifiers:
        # untimed shortcut for the remaining shares (identical values); kept
        # out of the serial stopwatch below
        pause = time.perf_counter()
        Hcm = sch._cert_message_hash(t, C_agg, d)
        for j in sch.Q[1:]:
            shares[j] = Hcm ** sch.z[j]
        round_start += time.perf_counter() - pause

    # (4) CertCombine -> Gamma_t
    comb_c = Clock()
    with comb_c:
        Gamma = sch.cert_combine_gamma(t, C_agg, d, shares)

    # (5) DC: AggrDec (incl. its VerifyCert gate) + DecProve -> Omega_t
    dc_c = Clock()
    with dc_c:
        Xt, Zt = sch.aggr_dec_gamma(Gamma)
        pi_dec = sch.dec_prove(Gamma, Xt, Zt)
    Omega = (Gamma, Xt, Zt, pi_dec)

    # (6) public Verify(Omega_t)
    ver_c = Clock()
    with ver_c:
        ok = sch.verify_omega(Omega)
    serial_wall = time.perf_counter() - round_start

    if not ok or Xt != sum(xs):
        raise AssertionError(f"round failed: verify={ok}, X={Xt}, expected {sum(xs)}")

    kq = k + 1
    derived = not measure_all_certifiers
    cert_wall_total = cert_wall[0] * kq if derived else sum(cert_wall)
    cert_cpu_total = cert_cpu[0] * kq if derived else sum(cert_cpu)

    stage_wall_sum = (sum(rep_wall) + build_c.wall + cert_wall_total
                      + comb_c.wall + dc_c.wall + ver_c.wall)
    total_cpu = (sum(rep_cpu) + build_c.cpu + cert_cpu_total
                 + comb_c.cpu + dc_c.cpu + ver_c.cpu)
    parallel_bound = (max(rep_wall) + build_c.wall + max(cert_wall)
                      + comb_c.wall + dc_c.wall + ver_c.wall)

    srt = sorted(rep_wall)
    sz = message_sizes(sch, ell_t, reports, C_agg, shares[sch.Q[0]], Gamma, Omega, label_mode)

    row = {
        'n': n, 'k': k, 'q_size': kq, 'L': L, 'trial': trial, 'label_mode': label_mode,
        'execution': 'sequential, single process',
        'serial_concurrency': 1, 'parallel_meters': n, 'parallel_certifiers': kq,
        'certifiers_executed': len(to_run), 'certifiers_derived': int(derived),
        # one-time (excluded from round totals)
        'setup_ms': ms(setup_c.wall), 'bsgs_precompute_ms': ms(bsgs_c.wall),
        # (1) meters
        'report_single_median_ms': ms(C._quantile(srt, 0.5)),
        'report_single_max_ms': ms(srt[-1]),
        'all_reports_serial_ms': ms(sum(rep_wall)),
        'all_reports_cpu_ms': ms(sum(rep_cpu)),
        # (2)-(6) stages
        'build_ms': ms(build_c.wall), 'build_cpu_ms': ms(build_c.cpu),
        'certshare_one_ms': ms(cert_wall[0]), 'certshare_max_ms': ms(max(cert_wall)),
        'cert_all_serial_ms': ms(cert_wall_total), 'cert_all_cpu_ms': ms(cert_cpu_total),
        'certcombine_ms': ms(comb_c.wall), 'certcombine_cpu_ms': ms(comb_c.cpu),
        'dc_ms': ms(dc_c.wall), 'dc_cpu_ms': ms(dc_c.cpu),
        'verify_ms': ms(ver_c.wall), 'verify_cpu_ms': ms(ver_c.cpu),
        # totals
        'serial_wall_ms': ms(serial_wall) if not derived else '',
        'serial_wall_est_ms': ms(stage_wall_sum),
        'parallel_compute_bound_ms': ms(parallel_bound),
        'total_cpu_ms': ms(total_cpu),
        'total_sent_B': total_bytes_sent(sz, n, k, '_B'),
        'total_sent_charm_B': total_bytes_sent(sz, n, k, '_charm_B'),
    }
    row.update(sz)
    return row


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

def _append(path, rows):
    if not rows:
        return
    new = not os.path.exists(path)
    with open(path, 'a', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        if new:
            w.writeheader()
        w.writerows(rows)


def _read(path):
    if not os.path.exists(path):
        return []
    with open(path, newline='') as f:
        return list(csv.DictReader(f))


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def summarize(trial_rows, out_dir, bandwidths, rtts):
    by_n = {}
    for r in trial_rows:
        by_n.setdefault(int(r['n']), []).append(r)
    summary, net_rows = [], []
    for n in sorted(by_n):
        rows = by_n[n]
        s = {'n': n, 'k': rows[0]['k'], 'q_size': rows[0]['q_size'], 'trials': len(rows),
             'certifiers_derived': rows[0]['certifiers_derived'],
             'label_mode': rows[0]['label_mode']}
        for key in rows[0]:
            if key in s or key in ('trial', 'execution', 'L'):
                continue
            vals = [_num(r[key]) for r in rows]
            vals = sorted(v for v in vals if v is not None)
            if not vals:
                continue
            s[key + '_median'] = C._quantile(vals, 0.5)
            s[key + '_q1'] = C._quantile(vals, 0.25)
            s[key + '_q3'] = C._quantile(vals, 0.75)
        summary.append(s)

        k = int(rows[0]['k'])
        sz = {key: float(rows[0][key]) for key in
              ('report_B', 'dist_msg_B', 'share_B', 'gamma_B', 'omega_B')}
        for bw in bandwidths:
            for rtt in rtts:
                net = network_ms(sz, n, k, bw, rtt)
                nr = {'n': n, 'k': k, 'bandwidth_mbps': bw, 'rtt_ms': rtt}
                nr.update(net)
                nr['parallel_compute_bound_ms'] = s['parallel_compute_bound_ms_median']
                nr['parallel_total_ms'] = s['parallel_compute_bound_ms_median'] + net['net_total_ms']
                nr['network_share_pct'] = 100 * net['net_total_ms'] / nr['parallel_total_ms']
                net_rows.append(nr)

    for name, rows in (('e2e_summary.csv', summary), ('e2e_network.csv', net_rows)):
        path = os.path.join(out_dir, name)
        if os.path.exists(path):
            os.remove(path)
        _append(path, rows)
    return summary, net_rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument('--smoke', action='store_true', help='tiny check: n = 10, 20; L = 8; 2 trials')
    ap.add_argument('--n', type=int, nargs='+', default=None, help=f'network sizes (default {N_SWEEP})')
    ap.add_argument('--trials', type=int, default=None, help='trials for every n (default: per-n schedule)')
    ap.add_argument('--k-pct', type=int, default=K_PCT)
    ap.add_argument('--L', type=int, default=16)
    ap.add_argument('--all-certifiers-up-to', type=int, default=100,
                    help='execute ALL k+1 certifiers when n <= this value; above it one certifier '
                         'is executed and the rest is derived (default 100; 0 = never)')
    ap.add_argument('--label', choices=('round', 'full'), default='round',
                    help='round label on the wire: 4-byte round number (default) or full ell_t')
    ap.add_argument('--bandwidth', type=float, nargs='+', default=[10, 100], help='Mbps')
    ap.add_argument('--rtt', type=float, nargs='+', default=[10, 50, 100], help='ms')
    ap.add_argument('--data', default=None, help='Excel file with real readings')
    ap.add_argument('--column', type=int, default=0)
    ap.add_argument('--no-header', action='store_true')
    ap.add_argument('--decimals', type=int, default=3)
    ap.add_argument('--seed', type=int, default=1234)
    ap.add_argument('--warmup', type=int, default=1)
    ap.add_argument('--out', default='e2e_results')
    ap.add_argument('--resume', action='store_true')
    args = ap.parse_args(argv)

    Ns = args.n or N_SWEEP
    L = args.L
    trials_of = {n: (args.trials or N_TRIALS.get(n, 3)) for n in Ns}
    if args.smoke:
        Ns, L = [10, 20], 8
        trials_of = {10: 2, 20: 2}

    os.makedirs(args.out, exist_ok=True)
    trials_csv = os.path.join(args.out, 'e2e_trials.csv')
    if os.path.exists(trials_csv) and not args.resume:
        print(f"{trials_csv} exists; use --resume or another --out. Nothing was run.")
        return 2

    dataset = None
    if args.data:
        dataset, _ = C.load_real_readings(args.data, args.decimals, column=args.column,
                                          has_header=not args.no_header)
        need = C.required_L(max(dataset))
        if need > L:
            print(f"NOTE: largest scaled reading needs L = {need}; raising L from {L}.")
            L = need

    data_source = (f"real dataset {args.data}" if args.data
                   else "synthetic uniform random readings in [0, 2^L)")
    env = C.environment_info('BN254', L, str(trials_of), args.warmup, args.seed, data_source,
                             f"n in {Ns}, k = ceil({args.k_pct}% of n)")
    env.update({
        'experiment': 'evaluation plan Section 1: one complete round Report -> Verify per trial',
        'execution': ('single process on one machine: all n meters and all k+1 certifiers run '
                      'SEQUENTIALLY (concurrency 1); messages passed in memory, no network'),
        'certifiers': (f"all k+1 certifiers executed when n <= {args.all_certifiers_up_to}; "
                       f"otherwise one executed and certification wall/CPU derived as (k+1) x one"),
        'cpu_timer': 'time.process_time() (CPU time of this process)',
        'parallel_bound': ('ANALYTICAL lower bound, zero network: max Report + Build + max CertShare '
                           '+ CertCombine + DC + Verify; n meters and k+1 certifiers concurrent'),
        'network_model': ('estimate: per stage RTT/2 + bytes*8/B on the bottleneck link; AG link '
                          'shared (n uploads, k+1 transcript copies serialized); no TCP handshake, '
                          'slow start, loss or header overhead'),
        'bandwidths_mbps': args.bandwidth, 'rtts_ms': args.rtt,
        'byte_encoding': (f"compressed BN254 sizes {NOMINAL}; i = {ID_BYTES} B; digest = "
                          f"{DIGEST_BYTES} B; X = fewest bytes holding n(2^L-1); label = "
                          f"{'4-byte round number (ell_t recomputed)' if args.label == 'round' else 'full ell_t'}"),
    })
    C.write_environment(env, os.path.join(args.out, 'e2e_env.txt'))
    print("Environment written to", os.path.join(args.out, 'e2e_env.txt'))

    if args.warmup:
        print(f"Warm-up: {args.warmup} untimed round(s) ...")
        C._warmup('BN254', L, args.warmup)

    done = {}
    for r in _read(trials_csv):
        done[int(r['n'])] = done.get(int(r['n']), 0) + 1

    rng = pyrandom.Random(args.seed)
    for n in Ns:
        k = min(math.ceil(args.k_pct / 100 * n), n - 2)
        all_cert = n <= args.all_certifiers_up_to
        for trial in range(trials_of[n]):
            xs = (C.get_dataset_values(dataset, n) if dataset is not None
                  else [rng.randint(0, 2 ** L - 1) for _ in range(n)])
            if trial < done.get(n, 0):
                continue
            t0 = time.perf_counter()
            row = run_round(n, k, L, trial, xs, all_cert, args.label)
            _append(trials_csv, [row])
            print(f"n={n:5d} k={k:4d} trial {trial + 1}/{trials_of[n]}: "
                  f"parallel bound {row['parallel_compute_bound_ms'] / 1000:8.2f} s, "
                  f"serial {row['serial_wall_est_ms'] / 1000:9.2f} s"
                  f"{' (derived)' if row['certifiers_derived'] else ' (measured)'}, "
                  f"CPU {row['total_cpu_ms'] / 1000:9.2f} s, "
                  f"bytes {row['total_sent_B'] / 1e6:8.2f} MB  "
                  f"[run took {time.perf_counter() - t0:.0f} s]")

    summary, net_rows = summarize(_read(trials_csv), args.out, args.bandwidth, args.rtt)
    print("\nMedian per n (seconds; parallel bound = analytical, zero network):")
    for s in summary:
        print(f"  n={s['n']:>5}  report {s['report_single_median_ms_median']:.1f} ms | "
              f"one CertShare {s['certshare_one_ms_median'] / 1000:.2f} s | "
              f"parallel bound {s['parallel_compute_bound_ms_median'] / 1000:.2f} s | "
              f"serial {s['serial_wall_est_ms_median'] / 1000:.2f} s | "
              f"CPU {s['total_cpu_ms_median'] / 1000:.2f} s | "
              f"sent {s['total_sent_B_median'] / 1e6:.2f} MB")
    print(f"\nWrote {trials_csv}, e2e_summary.csv, e2e_network.csv, e2e_env.txt in {args.out}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())