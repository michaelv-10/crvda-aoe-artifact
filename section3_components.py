"""
section3_components.py -- component breakdown and robustness checks
===============================================================================================

Part A (--part checks): the correctness/rejection tests listed in Section 3,
one test per item and named as in the plan. Every tampered report is
RE-SIGNED with the meter's own key (what a corrupted meter can do), so a
missing proof check cannot hide behind the report signature; the timing
dicts of VerifyRep / GoodTrans / Verify show WHICH check rejected it.

  1 changed ciphertext                 -> linking proof
  2 incorrect linking statement        -> linking proof (C encrypts x+1 but V commits x;
                                          C under another meter's AOE key)
  3 invalid range proof                -> range proof (x = 2^L; tampered proof field)
  4 changed report signature           -> signature check
  5 repeated or missing identity       -> GoodTrans check (i)
  6 altered transcript digest          -> GoodTrans check (v)
  7 incorrect BLS share                -> CertCombine share check
  8 incorrect recovery proof           -> Verify (recovery equations)
  9 repeated Report on the same label  -> returns EXACTLY the cached report (same
                                          bytes), also when called with another
                                          value; a new label gives a fresh report

Part B (--part timing): the full Report and GoodTrans paths BY COMPONENT,
measured inside the real code paths (crvda_aoe.py instruments report(),
verify_rep(), good_trans(), cert_share() and cert_combine() themselves; there
is no separate benchmark copy of any algorithm):

  Report (per meter; median over all n meters of the round)
    report_aoe_encrypt      AOE ciphertext C_i (incl. the two label hashes H1, H2)
    report_commit           plaintext commitment V_i = g1^x hx^gamma
    report_range_prove      Bulletproofs range proof
    report_link_prove       generalized Schnorr linking proof
    report_sign             report signature
    report_total            sum of the five components
    report_cached_query     a second Report query on the same label (cache hit)

  CertShare = GoodTrans + BLS share (one certifier, over all n reports)
    gt_sig_verify           n report-signature verifications
    gt_label_hash           n x (H1, H2) label hashes used by the linking check
    gt_link_verify          n linking-proof verifications
    gt_range_verify         n range-proof verifications
    gt_other                roster / order / label checks and loop overhead
    gt_aggcheck             C_t equals the product of the ciphertexts (check iv)
    gt_digest               transcript digest d_t (check v)
    certshare_bls_sign      BLS share theta_j = HC(CERT||M)^z_j
    certshare_total         sum of the above (= one certifier's CertShare)
    + per-report averages: gt_sig_verify_per_report, gt_link_verify_per_report,
      gt_range_verify_per_report

  CertCombine (AG; reported separately from CertShare)
    cc_hash                 HC(CERT||M_t), once
    cc_share_verify         k+1 share verifications (2 pairings each)
    cc_share_verify_per_share
    cc_multiply             product of the k+1 shares
    certcombine_total

  DC and public verification
    dc_certcheck, dc_mask, dc_dlog, dc_decprove, dc_total
    verify_valid            Verify on a legitimate Omega_t
    verify_invalid_cert     Verify on Omega_t with an altered certificate (rejects at VerifyCert)
    verify_invalid_X        Verify on Omega_t claiming X_t + 1 (rejects at the recovery equations)
    verify_invalid_proof    Verify on Omega_t with an incorrect recovery proof
    (measurement rule 3: benchmark Verify on legitimate AND invalid results)

Trials: one warm-up round, then per n: 10 (n <= 250), 5 (n = 500), 3 (n >= 750)
GoodTrans/CertCombine/DC trials; Report components use every meter of the
round as a sample; Verify cases 20 repetitions each. Median and IQR reported.

Usage
  python3 section3_components.py                    # Part A, then Part B for all n
  python3 section3_components.py --part checks      # Part A only (seconds)
  python3 section3_components.py --part timing --n 50 100
  python3 section3_components.py --data readings.xlsx   # real readings (as e2e_round.py)
  python3 section3_components.py --smoke
  caffeinate -i python3 section3_components.py | tee s3.log

Outputs (in --out, default s3_results; s3_smoke with --smoke)
  s3_checks.txt         Part A results
  s3_components.csv     n, k, path, component, median_ms, q1_ms, q3_ms, samples
  s3_env.txt
"""

import argparse
import csv
import math
import os
import platform
import random as pyrandom
import sys
import time

from charm.toolbox.pairinggroup import ZR

import crvda_aoe_v2 as C

N_SWEEP = [50, 100, 250, 500, 750, 1000]
N_TRIALS = {50: 10, 100: 10, 250: 10, 500: 5, 750: 3, 1000: 3}
K_PCT = 20
VERIFY_REPS = 20


class Log:
    def __init__(self, path):
        self.path, self.lines, self.fails = path, [], 0

    def __call__(self, msg=''):
        print(msg)
        self.lines.append(msg)

    def check(self, cond, msg):
        self(("  PASS: " if cond else "  FAIL: ") + msg)
        if not cond:
            self.fails += 1

    def save(self):
        with open(self.path, 'w') as f:
            f.write("\n".join(self.lines) + "\n")


# ---------------------------------------------------------------------------
# Part A: the Section 3 correctness / rejection list
# ---------------------------------------------------------------------------

def rejected_by(sch, R):
    """Which VerifyRep check rejected R (or 'ACCEPTED'). The first failing
    check short-circuits, so it is the last one that recorded time."""
    ok, tm = sch.verify_rep(R, return_timing=True)
    if ok:
        return 'ACCEPTED'
    if tm['range'] > 0:
        return 'range proof'
    if tm['link'] > 0:
        return 'linking proof'
    if tm['sig'] > 0:
        return 'signature'
    return 'identity/label syntax'


def part_checks(log, n=6, k=2, L=16, seed=5):
    rng = pyrandom.Random(seed)
    sch = C.CRVDA_AOE('BN254')
    sch.setup(n, k, L, sid=b'section3-checks')
    sch.build_bsgs()
    G, g1, hx = sch.group, sch.g1, sch.hx
    t = 3
    ell = sch.ell(t)
    A = C.hash_to_g1(G, b'H1', ell)
    B = C.hash_to_g1(G, b'H2', ell)
    xs = [rng.randint(0, 2 ** L - 1) for _ in range(n)]
    reports = [sch.report(i, t, xs[i - 1]) for i in range(1, n + 1)]

    def zr(v):
        return G.init(ZR, v)

    def signed(i, Ci, pi_val):
        msg = C.cat(G, b'REP', sch.sid, ell, i, Ci, pi_val)
        return (i, ell, Ci, pi_val, C.schnorr_sign(G, g1, sch.rsk[i], msg))

    def proofs(i, Ci, V, x_wit, s_wit, t_wit, gamma, x_range):
        lctx, rctx = [sch.sid, ell, i], [b'RANGE-CTX', sch.sid, ell, i]
        pl = C.link_prove(G, g1, sch.u, sch.h, hx, A, B, lctx, sch.K[i], Ci, V,
                          (x_wit, s_wit, t_wit, sch.rho[i], gamma))
        pr = C.range_prove_bp(G, g1, hx, sch.g_vec, sch.h_vec, V, x_range, gamma, L, rctx)
        return (V, pl, pr)

    i = 1
    x = xs[0]
    i_, ell_, Ci, pi_val, sig = reports[0]
    log.check(rejected_by(sch, reports[0]) == 'ACCEPTED', "honest report passes all VerifyRep checks")

    log("1. Changed ciphertext")
    v = rejected_by(sch, signed(i, Ci * g1, pi_val))
    log.check(v == 'linking proof', f"ciphertext changed, report re-signed: rejected by {v}")

    log("2. Incorrect linking statement")
    gam = G.random(ZR)
    V = (g1 ** zr(x)) * (hx ** gam)
    C_plus = (g1 ** zr(x + 1)) * (A ** sch.si[i]) * (B ** sch.ti[i])
    R = signed(i, C_plus, proofs(i, C_plus, V, zr(x), sch.si[i], sch.ti[i], gam, x))
    v = rejected_by(sch, R)
    log.check(v == 'linking proof', f"C encrypts x+1 while V commits to x: rejected by {v}")
    C_other = (g1 ** zr(x)) * (A ** sch.si[2]) * (B ** sch.ti[2])
    R = signed(i, C_other, proofs(i, C_other, V, zr(x), sch.si[2], sch.ti[2], gam, x))
    v = rejected_by(sch, R)
    log.check(v == 'linking proof', f"C under another meter's AOE key (statement K_i): rejected by {v}")

    log("3. Invalid range proof")
    big, gam = 2 ** L, G.random(ZR)
    Vb = (g1 ** zr(big)) * (hx ** gam)
    Cb = (g1 ** zr(big)) * (A ** sch.si[i]) * (B ** sch.ti[i])
    v = rejected_by(sch, signed(i, Cb, proofs(i, Cb, Vb, zr(big), sch.si[i], sch.ti[i], gam, big)))
    log.check(v == 'range proof', f"x = 2^L with a valid linking proof and signature: rejected by {v}")
    V0, pl0, pr0 = pi_val
    pr_bad = dict(pr0)
    pr_bad['tau_x'] = pr0['tau_x'] + zr(1)
    v = rejected_by(sch, signed(i, Ci, (V0, pl0, pr_bad)))
    log.check(v == 'range proof', f"range-proof field altered, report re-signed: rejected by {v}")

    log("4. Changed report signature")
    sR, sz = sig
    v = rejected_by(sch, (i, ell, Ci, pi_val, (sR, sz + zr(1))))
    log.check(v == 'signature', f"signature scalar changed: rejected by {v}")
    v = rejected_by(sch, (2, ell, Ci, pi_val, sig))
    log.check(v == 'signature', f"meter 1's report presented as meter 2's: rejected by {v}")

    log("5. Repeated or missing identity")
    T, Ct, d = sch.build(t, reports)

    def gt(Tx, Cx, dx):
        ok, tm = sch.good_trans(t, Tx, Cx, dx, return_timing=True)
        if ok:
            return 'ACCEPTED'
        if tm['digest'] > 0:
            return 'check (v) digest'
        if tm['aggcheck'] > 0:
            return 'check (iv) aggregate'
        return 'checks (i)-(iii) roster/label/VerifyRep'

    log.check(gt(T, Ct, d) == 'ACCEPTED', "honest transcript passes GoodTrans")
    dup = list(T)
    dup[1] = dup[0]
    v = gt(dup, Ct, d)
    log.check(v.startswith('checks (i)'), f"identity 1 repeated, identity 2 absent: rejected by GoodTrans {v}")
    v = gt(T[:-1], Ct, d)
    log.check(v.startswith('checks (i)'), f"identity {n} missing: rejected by GoodTrans {v}")
    v = gt(T + [T[0]], Ct, d)
    log.check(v.startswith('checks (i)'), f"extra copy of identity 1: rejected by GoodTrans {v}")

    log("6. Altered transcript digest")
    v = gt(T, Ct, bytes([d[0] ^ 1]) + d[1:])
    log.check(v == 'check (v) digest', f"one bit of d changed: rejected by GoodTrans {v}")

    log("7. Incorrect BLS share")
    shares = {j: sch.cert_share(j, t, T, Ct, d) for j in sch.Q}
    tau = sch.cert_combine(t, Ct, d, shares)
    log.check(sch.verify_cert(t, d, Ct, tau), "honest shares combine to a valid certificate")
    bad = dict(shares)
    bad[sch.Q[1]] = shares[sch.Q[1]] * g1
    try:
        sch.cert_combine(t, Ct, d, bad)
        v = 'ACCEPTED'
    except ValueError as e:
        v = str(e)
    log.check(f"quorum member {sch.Q[1]} failed" in v, f"altered share of member {sch.Q[1]}: CertCombine says '{v}'")
    other = sch._cert_message_hash(t, Ct * g1, d) ** sch.z[sch.Q[1]]
    bad[sch.Q[1]] = other
    try:
        sch.cert_combine(t, Ct, d, bad)
        v = 'ACCEPTED'
    except ValueError as e:
        v = str(e)
    log.check(f"quorum member {sch.Q[1]} failed" in v, f"share signed over a different aggregate: CertCombine says '{v}'")

    log("8. Incorrect recovery proof")
    Gamma = sch.make_gamma(t, Ct, d, tau)
    Xt, Zt = sch.aggr_dec_gamma(Gamma)
    D1, D2, D3, ys, yt = sch.dec_prove(Gamma, Xt, Zt)
    log.check(sch.verify_omega((Gamma, Xt, Zt, (D1, D2, D3, ys, yt))) and Xt == sum(xs),
              f"honest Omega_t verifies and X_t = {Xt} is the true sum")

    def ver(O):
        ok, tm = sch.verify_omega(O, return_timing=True)
        if ok:
            return 'ACCEPTED'
        return 'recovery equations' if tm['recovery'] > 0 else 'VerifyCert'

    for label, pi in (("ys altered", (D1, D2, D3, ys + zr(1), yt)),
                      ("D3 altered", (D1, D2, D3 * g1, ys, yt)),
                      ("a proof made for a different Z_t", sch.dec_prove(Gamma, Xt, Zt * g1))):
        v = ver((Gamma, Xt, Zt, pi))
        log.check(v == 'recovery equations', f"recovery proof with {label}: rejected by Verify, {v}")
    v = ver((Gamma, Xt + 1, Zt, (D1, D2, D3, ys, yt)))
    log.check(v == 'recovery equations', f"Omega_t claiming X_t + 1: rejected by Verify, {v}")

    log("9. Repeated Report on the same label")
    first = sch.report(1, t, xs[0])
    enc = C.to_bytes(G, first)
    t0 = time.perf_counter()
    again = sch.report(1, t, xs[0])
    dt = time.perf_counter() - t0
    log.check(again is first and C.to_bytes(G, again) == enc,
              f"second query, same value: returns exactly the cached report ({dt * 1e6:.1f} us, no new encryption)")
    other_val = sch.report(1, t, (xs[0] + 12345) % (2 ** L))
    log.check(other_val is first and C.to_bytes(G, other_val) == enc,
              "second query with a DIFFERENT value: still the cached report (one ciphertext per meter and label)")
    fresh = sch.report(1, t + 1, xs[0])
    log.check(C.to_bytes(G, fresh) != enc and fresh[2] != first[2],
              "a new label (next round) produces a fresh report and ciphertext")
    T2, C2, d2 = sch.build(t, [first] + [sch.report(i2, t, xs[i2 - 1]) for i2 in range(2, n + 1)])
    log.check(d2 == d and C2 == Ct, "re-querying all meters for the same label rebuilds the identical transcript")


# ---------------------------------------------------------------------------
# Part B: component timing
# ---------------------------------------------------------------------------

def q(vals, p):
    return C._quantile(sorted(vals), p)


def time_point(n, k, L, trials, xs, sid):
    sch = C.CRVDA_AOE('BN254')
    sch.setup(n, k, L, sid=sid)
    sch.build_bsgs()
    G, g1 = sch.group, sch.g1
    t = 1
    S = {}

    def add(path, comp, v):
        S.setdefault((path, comp), []).append(v)

    # ---- Report: every meter of the round is one sample ----
    reports = []
    for i in range(1, n + 1):
        R, tm = sch.report(i, t, xs[i - 1], return_timing=True)
        reports.append(R)
        add('Report', 'report_aoe_encrypt', tm['encrypt'])
        add('Report', 'report_commit', tm['commit'])
        add('Report', 'report_range_prove', tm['range'])
        add('Report', 'report_link_prove', tm['link'])
        add('Report', 'report_sign', tm['sign'])
        add('Report', 'report_total', tm['encrypt'] + tm['proofgen'] + tm['sign'])
    for i in range(1, min(n, 50) + 1):
        t0 = time.perf_counter()
        sch.report(i, t, xs[i - 1])
        add('Report', 'report_cached_query', time.perf_counter() - t0)

    T, Ct, d = sch.build(t, reports)
    j0 = sch.Q[0]

    # ---- CertShare = GoodTrans + BLS share, one certifier ----
    for _ in range(trials):
        share, tm = sch.cert_share(j0, t, T, Ct, d, return_timing=True)
        add('CertShare', 'gt_sig_verify', tm['rep_sig'])
        add('CertShare', 'gt_label_hash', tm['rep_label'])
        add('CertShare', 'gt_link_verify', tm['rep_link'])
        add('CertShare', 'gt_range_verify', tm['rep_range'])
        add('CertShare', 'gt_other', tm['rep_other'])
        add('CertShare', 'gt_aggcheck', tm['aggcheck'])
        add('CertShare', 'gt_digest', tm['digest'])
        add('CertShare', 'certshare_bls_sign', tm['bls'])
        add('CertShare', 'goodtrans_total', tm['reportcheck'] + tm['aggcheck'] + tm['digest'])
        add('CertShare', 'certshare_total', tm['reportcheck'] + tm['aggcheck'] + tm['digest'] + tm['bls'])
        add('CertShare', 'gt_sig_verify_per_report', tm['rep_sig'] / n)
        add('CertShare', 'gt_link_verify_per_report', tm['rep_link'] / n)
        add('CertShare', 'gt_range_verify_per_report', tm['rep_range'] / n)

    # ---- CertCombine (separate from CertShare) ----
    Hcm = sch._cert_message_hash(t, Ct, d)
    shares = {j: Hcm ** sch.z[j] for j in sch.Q}     # identical to the CertShare outputs
    assert shares[j0] == share
    for _ in range(trials):
        tau, tm = sch.cert_combine(t, Ct, d, shares, return_timing=True)
        add('CertCombine', 'cc_hash', tm['hash'])
        add('CertCombine', 'cc_share_verify', tm['sharechecks'] - tm['hash'])
        add('CertCombine', 'cc_share_verify_per_share', (tm['sharechecks'] - tm['hash']) / (k + 1))
        add('CertCombine', 'cc_multiply', tm['multiply'])
        add('CertCombine', 'certcombine_total', tm['sharechecks'] + tm['multiply'])

    # ---- DC ----
    Gamma = sch.make_gamma(t, Ct, d, tau)
    for _ in range(trials):
        Xt, Zt, tm = sch.aggr_dec_gamma(Gamma, return_timing=True)
        t0 = time.perf_counter()
        pi = sch.dec_prove(Gamma, Xt, Zt)
        tp = time.perf_counter() - t0
        add('DC', 'dc_certcheck', tm['certcheck'])
        add('DC', 'dc_mask', tm['mask'])
        add('DC', 'dc_dlog', tm['dlog'])
        add('DC', 'dc_decprove', tp)
        add('DC', 'dc_total', tm['certcheck'] + tm['mask'] + tm['dlog'] + tp)
    assert Xt == sum(xs)

    # ---- Verify on legitimate and invalid results ----
    D1, D2, D3, ys, yt = pi
    one = G.init(ZR, 1)
    ell_t = Gamma[0]
    cases = {
        'verify_valid': ((Gamma, Xt, Zt, pi), True),
        'verify_invalid_cert': (((ell_t, d, Ct, tau * g1), Xt, Zt, pi), False),
        'verify_invalid_X': ((Gamma, Xt + 1, Zt, pi), False),
        'verify_invalid_proof': ((Gamma, Xt, Zt, (D1, D2, D3, ys + one, yt)), False),
    }
    for name, (O, expect) in cases.items():
        for _ in range(VERIFY_REPS):
            t0 = time.perf_counter()
            ok = sch.verify_omega(O)
            add('Verify', name, time.perf_counter() - t0)
            assert ok == expect, f"{name}: Verify returned {ok}"
    return S


def part_timing(log, Ns, k_pct, L, seed, out_dir, data, trials_override):
    rows = []
    rng = pyrandom.Random(seed)
    for n in Ns:
        k = min(math.ceil(k_pct / 100 * n), n - 2)
        trials = trials_override or N_TRIALS.get(n, 3)
        xs = (C.get_dataset_values(data, n) if data is not None
              else [rng.randint(0, 2 ** L - 1) for _ in range(n)])
        t0 = time.perf_counter()
        S = time_point(n, k, L, trials, xs, sid=f"s3-{n}".encode())
        for (path, comp), vals in S.items():
            rows.append({'n': n, 'k': k, 'path': path, 'component': comp,
                         'median_ms': q(vals, 0.5) * 1000, 'q1_ms': q(vals, 0.25) * 1000,
                         'q3_ms': q(vals, 0.75) * 1000, 'samples': len(vals)})
        med = {c: q(v, 0.5) * 1000 for (_, c), v in S.items()}
        log(f"n={n:5d} k={k:4d}: Report {med['report_total']:.1f} ms "
            f"(enc {med['report_aoe_encrypt']:.1f}, commit {med['report_commit']:.1f}, "
            f"range {med['report_range_prove']:.1f}, link {med['report_link_prove']:.1f}, "
            f"sign {med['report_sign']:.1f}) | CertShare {med['certshare_total'] / 1000:.2f} s "
            f"(sig {med['gt_sig_verify'] / 1000:.2f}, link {med['gt_link_verify'] / 1000:.2f}, "
            f"range {med['gt_range_verify'] / 1000:.2f}, BLS {med['certshare_bls_sign']:.2f} ms) | "
            f"CertCombine {med['certcombine_total'] / 1000:.2f} s "
            f"({med['cc_share_verify_per_share']:.1f} ms/share) | "
            f"Verify {med['verify_valid']:.1f} ms  [{time.perf_counter() - t0:.0f} s]")
        with open(os.path.join(out_dir, 's3_components.csv'), 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument('--part', choices=('checks', 'timing', 'all'), default='all')
    ap.add_argument('--n', type=int, nargs='+', default=None)
    ap.add_argument('--trials', type=int, default=None, help='trials for every n (default: per-n schedule)')
    ap.add_argument('--k-pct', type=int, default=K_PCT)
    ap.add_argument('--L', type=int, default=16)
    ap.add_argument('--seed', type=int, default=1234)
    ap.add_argument('--data', default=None, help='Excel file with real readings')
    ap.add_argument('--column', type=int, default=0)
    ap.add_argument('--no-header', action='store_true')
    ap.add_argument('--decimals', type=int, default=3)
    ap.add_argument('--smoke', action='store_true')
    ap.add_argument('--out', default=None)
    args = ap.parse_args(argv)

    out_dir = args.out or ('s3_smoke' if args.smoke else 's3_results')
    os.makedirs(out_dir, exist_ok=True)
    Ns = [10, 20] if args.smoke else (args.n or N_SWEEP)
    L = args.L
    data = None
    if args.data:
        data, _ = C.load_real_readings(args.data, args.decimals, column=args.column,
                                       has_header=not args.no_header)
        L = max(L, C.required_L(max(data)))

    with open(os.path.join(out_dir, 's3_env.txt'), 'w') as f:
        f.write(f"python: {sys.version.split()[0]}\nplatform: {platform.platform()}\n"
                f"machine: {platform.machine()}\ncharm: {C._charm_version()}\ncurve: BN254\nL: {L}\n"
                f"n: {Ns}\nk: ceil({args.k_pct}% of n)\ntrials: {args.trials or N_TRIALS}\n"
                f"data: {args.data or 'synthetic uniform readings'}\ntimer: time.perf_counter, "
                f"single process, sequential; one warm-up round\n")

    log = Log(os.path.join(out_dir, 's3_checks.txt'))
    if args.part in ('checks', 'all'):
        log("== Part A: Section 3 correctness / rejection tests ==")
        part_checks(log, L=L)
        log(f"Part A: {'ALL PASSED' if log.fails == 0 else f'{log.fails} FAILED'}")
        log.save()
        if log.fails:
            return 1
    if args.part in ('timing', 'all'):
        log("\n== Part B: component timing (medians) ==")
        C._warmup('BN254', L, 1)
        part_timing(log, Ns, args.k_pct, L, args.seed, out_dir, data,
                    1 if args.smoke else args.trials)
        log(f"Wrote s3_components.csv in {out_dir}")
    log.save()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())