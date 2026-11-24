"""
concurrency_test.py -- concurrent certifiers on one machine
==================================================================================

"Practical concurrency test":
  "If 201 physical certifiers are unavailable, run 1, 2, 4, and 8 independent workers on
   available hardware, measure contention and completion time, and report separately an
   explicitly estimated 201-certifier scenario."

What it does
------------
1. Setup for n meters, k = ceil(20% of n) (default n = 1000, k = 200), L = 16.
2. Every meter runs Report; each report is ENCODED TO BYTES with the wire codec (timed:
   this fills the "wire encoding of R_i" row of Table II).
3. The AG runs Build and encodes the transcript message (t, d_t, C_t, T_t) -- the exact
   bytes a certifier receives.
4. For each w in {1, 2, 4, 8} and each trial, w INDEPENDENT PROCESSES are started. Each
   process is one certifier j: it decodes the public parameters and its own key, DECODES
   the transcript bytes (timed: fills the "decoding the transcript" row of Table II), waits
   at a barrier so all w start together, then runs CertShare = GoodTrans + BLS share
   (wall-clock and CPU time). Nothing is skipped: every signature, linking proof and range
   proof is verified by every worker.
5. The parent checks every returned share against the expected value H_C(CERT||M_t)^{z_j},
   so a worker that did not complete GoodTrans is detected.
6. Trials are interleaved (w = 1, 2, 4, 8, then again) so thermal drift affects all w alike.

Outputs (in --out, default results_concurrency/)
  concurrency_trials.csv   one row per (trial, w, worker)
  concurrency_summary.csv  one row per w: medians + slowdown vs w = 1
  concurrency_wire.csv     encode-report / decode-transcript timings
  concurrency_env.txt      platform, core counts (P/E on Apple silicon), versions, parameters

Usage
  python3 concurrency_test.py --smoke                 # n = 20, k = 4, w = 1,2 (a minute)
  python3 concurrency_test.py                         # n = 1000, k = 200, w = 1,2,4,8, 3 trials
  python3 concurrency_test.py --trials 5 --workers 1 2 4 8
  python3 concurrency_test.py --data readings.xlsx    # same real readings as e2e_round.py
  caffeinate -i python3 concurrency_test.py | tee concurrency.log      # macOS: keep awake

Notes for the paper
  * "Cores used" is the number of simultaneous worker processes; the OS chooses the cores.
    An Apple M4 has 4 performance + 6 efficiency cores, so w = 8 necessarily uses
    efficiency cores; the env file records the P/E counts.
  * Completion of all w = latest end - earliest start (wall clock, all workers started
    together at the barrier). Slowdown = median per-worker GoodTrans at w / median at w = 1.
  * The 201-certifier critical path stays an ESTIMATE: it assumes each certifier is its own
    device, i.e. the w = 1 time. This test shows whether running several certifiers on
    shared hardware changes that time.
"""
import argparse
import csv
import math
import multiprocessing as mp
import os
import platform
import random as pyrandom
import statistics
import subprocess
import sys
import time

import crvda_aoe_v2 as C
from crvda_wire import Wire


# ---------------------------------------------------------------------------
# worker (runs in a fresh, spawned process)
# ---------------------------------------------------------------------------

def _worker(j, pub, cert_secret, dist, barrier, out_q):
    try:
        import crvda_aoe as C2
        from crvda_wire import Wire as Wire2
        group = C2.CRVDA_AOE('BN254').group
        W = Wire2(group)
        me = W.add_secret(W.dec_public(pub), cert_secret)       # untimed: one-time key loading

        t0w, t0c = time.perf_counter(), time.process_time()
        t, T, Ct, d = W.dec_dist(me, dist)                       # decode the received transcript
        dec_wall, dec_cpu = time.perf_counter() - t0w, time.process_time() - t0c

        barrier.wait()                                           # all w workers start together
        start_epoch = time.time()
        t1w, t1c = time.perf_counter(), time.process_time()
        share = me.cert_share(j, t, T, Ct, d)                    # GoodTrans + BLS share (raises if rejected)
        gt_wall, gt_cpu = time.perf_counter() - t1w, time.process_time() - t1c
        end_epoch = time.time()

        out_q.put({'j': j, 'ok': True, 'share': W.enc_share(share),
                   'decode_ms': dec_wall * 1000, 'decode_cpu_ms': dec_cpu * 1000,
                   'goodtrans_ms': gt_wall * 1000, 'goodtrans_cpu_ms': gt_cpu * 1000,
                   'start_epoch': start_epoch, 'end_epoch': end_epoch, 'pid': os.getpid()})
    except Exception as e:                                       # report, never hang the parent
        try:
            barrier.abort()
        except Exception:
            pass
        out_q.put({'j': j, 'ok': False, 'error': repr(e)})


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def sysctl(name):
    try:
        return subprocess.run(['sysctl', '-n', name], capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return ''


def environment(args, n, k, L):
    env = {
        'experiment': 'w concurrent certifier processes on one machine, each running CertShare '
                      '(GoodTrans + BLS share) on the same encoded n-report transcript',
        'python': sys.version.split()[0],
        'platform': platform.platform(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'cpu_brand': sysctl('machdep.cpu.brand_string'),
        'logical_cpus': os.cpu_count(),
        'perf_cores (hw.perflevel0.physicalcpu)': sysctl('hw.perflevel0.physicalcpu'),
        'efficiency_cores (hw.perflevel1.physicalcpu)': sysctl('hw.perflevel1.physicalcpu'),
        'memory_bytes': sysctl('hw.memsize'),
        'curve': 'BN254', 'n': n, 'k': k, 'L': L,
        'workers': args.workers, 'trials': args.trials, 'seed': args.seed,
        'data': args.data or 'synthetic uniform random readings in [0, 2^L)',
        'start_method': 'spawn (each worker is a fresh process)',
        'timers': 'time.perf_counter (wall), time.process_time (CPU of the worker), time.time (cross-process completion)',
    }
    try:
        import importlib.metadata as md
        env['charm-crypto-framework'] = md.version('charm-crypto-framework')
    except Exception:
        env['charm-crypto-framework'] = 'unknown'
    return env


def med(xs):
    return statistics.median(xs) if xs else float('nan')


def iqr(xs):
    if len(xs) < 2:
        return (float('nan'), float('nan'))
    q = statistics.quantiles(xs, n=4, method='inclusive')
    return q[0], q[2]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--n', type=int, default=1000)
    ap.add_argument('--k-pct', type=float, default=20.0)
    ap.add_argument('--L', type=int, default=16)
    ap.add_argument('--workers', type=int, nargs='+', default=[1, 2, 4, 8])
    ap.add_argument('--trials', type=int, default=3)
    ap.add_argument('--seed', type=int, default=1234)
    ap.add_argument('--data', default=None, help='Excel file with real readings (as e2e_round.py)')
    ap.add_argument('--decimals', type=int, default=3)
    ap.add_argument('--column', type=int, default=0)
    ap.add_argument('--no-header', action='store_true')
    ap.add_argument('--out', default='results_concurrency')
    ap.add_argument('--smoke', action='store_true', help='n = 20, k = 4, w = 1 2, 1 trial')
    args = ap.parse_args()
    if args.smoke:
        args.n, args.workers, args.trials = 20, [1, 2], 1

    n, L = args.n, args.L
    k = min(math.ceil(args.k_pct / 100 * n), n - 2)
    need = max(args.workers)
    if need > k + 1:
        sys.exit(f"--workers needs {need} certifiers but the quorum has only k+1 = {k + 1}")
    os.makedirs(args.out, exist_ok=True)

    env = environment(args, n, k, L)
    with open(os.path.join(args.out, 'concurrency_env.txt'), 'w') as fh:
        for kk, v in env.items():
            fh.write(f"{kk}: {v}\n")
    print(f"n = {n}, k = {k}, L = {L}; workers {args.workers}; {args.trials} trial(s)")
    print(f"CPU: {env['cpu_brand'] or env['processor']}; logical CPUs {env['logical_cpus']}; "
          f"P/E cores {env['perf_cores (hw.perflevel0.physicalcpu)'] or '?'}/"
          f"{env['efficiency_cores (hw.perflevel1.physicalcpu)'] or '?'}")

    # ---- inputs
    rng = pyrandom.Random(args.seed)
    if args.data:
        dataset, _ = C.load_real_readings(args.data, args.decimals, column=args.column,
                                          has_header=not args.no_header)
        xs = C.get_dataset_values(dataset, n)
        if C.required_L(max(xs)) > L:
            sys.exit(f"the readings need L = {C.required_L(max(xs))} > {L}")
    else:
        xs = [rng.randint(0, 2 ** L - 1) for _ in range(n)]

    # ---- setup, reports (encoded), build
    t_s = time.perf_counter()
    dealer = C.CRVDA_AOE('BN254')
    dealer.setup(n, k, L, sid=f"concurrency-{n}-{k}".encode())
    W = Wire(dealer.group)
    pub = W.enc_public(dealer)
    print(f"Setup done in {time.perf_counter() - t_s:.1f} s; point encoding "
          f"{'compact' if W.compact else 'Charm raw (fallback)'}")

    t = 1
    reports, enc_ms, rep_bytes = [], [], None
    t_r = time.perf_counter()
    for i in range(1, n + 1):
        R = dealer.report(i, t, xs[i - 1])
        a = time.perf_counter()
        b = W.enc_report(dealer, R, t)
        enc_ms.append((time.perf_counter() - a) * 1000)
        rep_bytes = b
        reports.append(R)
        if i % 100 == 0:
            print(f"  {i}/{n} reports ({time.perf_counter() - t_r:.0f} s)")
    T, Ct, d = dealer.build(t, reports)
    dist = W.enc_dist(dealer, t, T, Ct, d)
    assert len(dist) == W.dist_len(n, L), "transcript message has an unexpected length"
    Hcm = dealer._cert_message_hash(t, Ct, d)
    certs = list(dealer.Q)[:need]
    expected = {j: W.enc_share(Hcm ** dealer.z[j]) for j in certs}
    secrets = {j: W.enc_cert_secret(dealer, j) for j in certs}
    print(f"Reports + Build done; report {len(rep_bytes)} B, transcript message {len(dist):,} B")

    # ---- runs
    ctx = mp.get_context('spawn')
    rows = []
    for trial in range(args.trials):
        for w in args.workers:
            barrier = ctx.Barrier(w)
            q = ctx.Queue()
            procs = [ctx.Process(target=_worker, args=(j, pub, secrets[j], dist, barrier, q)) for j in certs[:w]]
            for p in procs:
                p.start()
            res = [q.get() for _ in procs]
            for p in procs:
                p.join()
            bad = [r for r in res if not r['ok']]
            if bad:
                sys.exit(f"worker failed (trial {trial}, w = {w}): {bad[0]['error']}")
            for r in res:
                if r['share'] != expected[r['j']]:
                    sys.exit(f"worker j = {r['j']} returned a wrong share (trial {trial}, w = {w})")
            t0 = min(r['start_epoch'] for r in res)
            t1 = max(r['end_epoch'] for r in res)
            for r in res:
                rows.append({'trial': trial, 'w': w, 'j': r['j'], 'pid': r['pid'],
                             'decode_ms': r['decode_ms'], 'decode_cpu_ms': r['decode_cpu_ms'],
                             'goodtrans_ms': r['goodtrans_ms'], 'goodtrans_cpu_ms': r['goodtrans_cpu_ms'],
                             'start_offset_ms': (r['start_epoch'] - t0) * 1000,
                             'completion_all_ms': (t1 - t0) * 1000})
            gts = [r['goodtrans_ms'] / 1000 for r in res]
            print(f"trial {trial + 1}/{args.trials}, w = {w}: GoodTrans per worker median {med(gts):.2f} s, "
                  f"max {max(gts):.2f} s, all done in {t1 - t0:.2f} s; shares verified")

    # ---- write
    with open(os.path.join(args.out, 'concurrency_trials.csv'), 'w', newline='') as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0]))
        wr.writeheader()
        wr.writerows(rows)

    summ = []
    base = None
    for w in args.workers:
        rs = [r for r in rows if r['w'] == w]
        gt = [r['goodtrans_ms'] for r in rs]
        comp = sorted({(r['trial'], r['completion_all_ms']) for r in rs})
        comp = [c for _, c in comp]
        s = {'w': w, 'samples': len(gt),
             'goodtrans_median_ms': med(gt), 'goodtrans_q1_ms': iqr(gt)[0], 'goodtrans_q3_ms': iqr(gt)[1],
             'goodtrans_max_ms': max(gt),
             'goodtrans_cpu_median_ms': med([r['goodtrans_cpu_ms'] for r in rs]),
             'completion_median_ms': med(comp), 'completion_max_ms': max(comp),
             'max_start_offset_ms': max(r['start_offset_ms'] for r in rs)}
        if base is None:
            base = s['goodtrans_median_ms']
        s['slowdown_vs_w1'] = s['goodtrans_median_ms'] / base
        summ.append(s)
    with open(os.path.join(args.out, 'concurrency_summary.csv'), 'w', newline='') as fh:
        wr = csv.DictWriter(fh, fieldnames=list(summ[0]))
        wr.writeheader()
        wr.writerows(summ)

    dec = [r['decode_ms'] for r in rows]
    wire = {'n': n, 'report_B': len(rep_bytes), 'encode_report_median_ms': med(enc_ms),
            'encode_report_q1_ms': iqr(enc_ms)[0], 'encode_report_q3_ms': iqr(enc_ms)[1],
            'transcript_B': len(dist), 'decode_transcript_median_ms': med(dec),
            'decode_transcript_q1_ms': iqr(dec)[0], 'decode_transcript_q3_ms': iqr(dec)[1],
            'decode_samples': len(dec)}
    with open(os.path.join(args.out, 'concurrency_wire.csv'), 'w', newline='') as fh:
        wr = csv.DictWriter(fh, fieldnames=list(wire))
        wr.writeheader()
        wr.writerow(wire)

if __name__ == '__main__':
    mp.freeze_support()
    main()