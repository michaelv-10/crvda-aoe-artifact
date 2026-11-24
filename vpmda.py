"""
vpmda.py -- implementation of VPMDA, following the published scheme definition
===================================================================================

"Enabling Verifiable Privacy-Preserving Multi-Type Data Aggregation in Smart Grids"
Two variants, both exactly as published:
  variant='main'      Sec. 4.2: Initialization, Data Reporting, Data Aggregation,
                      Verification and Decryption (CC: n + 2 pairings)
  variant='extended'  Sec. 5 "Performance Improvement": AG additionally keeps the
                      secret psi_i; CC: 2 pairings. This variant ADDS the trust
                      assumption that AG keeps psi_1..psi_n secret (paper's Remark,
                      Sec. 3.2).
Usage
  python3 vpmda.py --check                         # correctness + verification tests (both variants)
  caffeinate -i python3 vpmda.py --bench           # timing sweep, extended variant (default)
  python3 vpmda.py --bench --variant main          # the Sec. 4.2 scheme
  python3 vpmda.py --bench --n 50 100 --trials 3 --paillier-bits 3072 --k 1
  python3 vpmda.py --bench --data readings.xlsx    # real readings (as in our other scripts)

Outputs (in --out, default vpmda_results_<variant>)
  vpmda_trials.csv   one row per (n, trial): every stage, unrounded
  vpmda_summary.csv  per n: median, q1, q3 of every column
  vpmda_env.txt      parameters, platform, library versions, stage definitions
"""

import argparse
import csv
import hashlib
import hmac
import math
import os
import platform
import secrets
import sys
import time

import gmpy2
from gmpy2 import mpz

from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR, pair


# ---------------------------------------------------------------------------
# Paillier key generation (TTP)
# ---------------------------------------------------------------------------

def _prime(bits):
    while True:
        cand = mpz(secrets.randbits(bits)) | (mpz(1) << (bits - 1)) | 1
        p = gmpy2.next_prime(cand)
        if p.bit_length() == bits:
            return p


def paillier_keygen(bits):
    while True:
        q1, q2 = _prime(bits // 2), _prime(bits // 2)
        if q1 == q2:
            continue
        N = q1 * q2
        if gmpy2.gcd(N, (q1 - 1) * (q2 - 1)) != 1:
            continue
        lam = gmpy2.lcm(q1 - 1, q2 - 1)
        return N, lam


# ---------------------------------------------------------------------------
# VPMDA
# ---------------------------------------------------------------------------

class VPMDA:
    def __init__(self, n, k=1, eta=None, paillier_bits=2048, variant='extended', curve='BN254'):
        if variant not in ('main', 'extended'):
            raise ValueError("variant must be 'main' or 'extended'")
        self.n, self.k, self.variant = n, k, variant
        self.eta = list(eta) if eta is not None else [2 ** 16 - 1] * k   # upper bound of each data type
        if len(self.eta) != k:
            raise ValueError("eta must give one upper bound per data type")
        self.paillier_bits = paillier_bits
        self.group = PairingGroup(curve)
        self.p = int(self.group.order())

    # ---- hash functions -------------------------------------------------------

    def H(self, att):                                   # H: {0,1}* -> G1
        return self.group.hash(att, G1)

    def h1(self, T):                                    # h1: {0,1}* -> Z*_N
        N = self.N
        nbytes = (N.bit_length() + 64 + 7) // 8
        ctr = 0
        while True:
            out, c = b'', 0
            while len(out) < nbytes:
                out += hashlib.sha256(b'VPMDA-h1|' + str(T).encode() + b'|' + ctr.to_bytes(4, 'big')
                                      + c.to_bytes(4, 'big')).digest()
                c += 1
            v = mpz(int.from_bytes(out[:nbytes], 'big')) % N
            if v != 0 and gmpy2.gcd(v, N) == 1:
                return v
            ctr += 1

    def h2(self, gamma):                                # h2: Z*_N -> Z_p (Z*_p in Sec. 5)
        v = int.from_bytes(hashlib.sha256(b'VPMDA-h2|' + int(gamma).to_bytes(
            (self.N.bit_length() + 7) // 8, 'big')).digest(), 'big') % self.p
        return v if v != 0 else 1

    def h3(self, x, nonce):                             # h3: Z*_{N^2} x {0,1}* -> Z_p
        xb = int(x).to_bytes((self.N2.bit_length() + 7) // 8, 'big')
        return int.from_bytes(hashlib.sha256(b'VPMDA-h3|' + xb + b'|' + nonce).digest(), 'big') % self.p

    def prg(self, sk, nonce):                           # prg: SK_prg x I -> Z_p^{n-1}
        return [int.from_bytes(hmac.new(sk, nonce + i.to_bytes(4, 'big'), hashlib.sha256).digest(),
                               'big') % self.p for i in range(1, self.n)]

    def zr(self, v):
        return self.group.init(ZR, int(v) % self.p)

    # ---- Initialization (TTP) ----------------------------------------------------

    def setup(self, raid=b'RAID-1'):
        G, n, k = self.group, self.n, self.k
        N, lam = paillier_keygen(self.paillier_bits)
        self.N, self.N2 = N, N * N
        self.rho = G.random(G2)                          # generator (G2 under the asymmetric adaptation)
        self.nu = G.random(G1)

        gammas = [mpz(secrets.randbelow(int(N) - 1) + 1) for _ in range(n)]
        while any(gmpy2.gcd(gm, N) != 1 for gm in gammas):
            gammas = [mpz(secrets.randbelow(int(N) - 1) + 1) for _ in range(n)]
        gamma0 = (-sum(gammas)) % lam
        gamma_prime = (-gamma0) % lam
        h2v = [self.h2(gm) for gm in gammas]

        self.att = [raid + b'||' + str(i).encode() for i in range(1, n + 1)]
        self.H_att = [self.H(a) for a in self.att]

        if self.variant == 'main':
            self.beta = [self.rho ** self.zr(h) for h in h2v]           # beta_i = rho^{h2(gamma_i)}
            self.psi = None
        else:
            pi = 1
            for h in h2v:
                pi = (pi * h) % self.p
            self.beta = self.rho ** self.zr(pi)                        # beta = rho^pi  (public)
            self.psi = [(h * pi) % self.p for h in h2v]               # psi_i = h2(gamma_i) pi (AG only)

        # superincreasing sequence omega_1..omega_2k, eta_{k+j} = eta_j^2
        etas = self.eta + [e * e for e in self.eta]
        omega = [1]
        for a in range(1, 2 * k):
            bound = sum(omega[j] * etas[j] * n for j in range(a))
            omega.append(bound + 1)
        if sum(omega[j] * etas[j] * n for j in range(2 * k)) >= N:
            raise ValueError("encoded aggregate would not fit in Z_N: increase N or reduce n/eta")
        self.omega = omega

        # secrets, kept per party
        self.sm_gamma = gammas                                          # SM_i: gamma_i
        self.sm_h2 = h2v                                                # SM_i derives h2(gamma_i) itself
        self.sm_h2_inv = [int(gmpy2.invert(h, self.p)) for h in h2v] if self.variant == 'extended' else None
        self.cc_gamma0, self.cc_gamma_prime = gamma0, gamma_prime       # CC
        self.sk_prg = secrets.token_bytes(32)                           # shared by CC and AG
        del lam                                                         # TTP destroys lambda

    # ---- Data Reporting (SM_i) ------------------------------------------------------

    def sm_report(self, i, msgs, T, timing=None):
        """i is 0-based; msgs = [m_i1, ..., m_ik]. Returns (CT_i, sigma_i, T)."""
        if len(msgs) != self.k or any(not (0 <= m <= e) for m, e in zip(msgs, self.eta)):
            raise ValueError("readings must satisfy 0 <= m_ij <= eta_j")
        k, N, N2 = self.k, self.N, self.N2
        t0 = time.perf_counter()
        E = sum(self.omega[j] * msgs[j] + self.omega[k + j] * msgs[j] * msgs[j] for j in range(k))
        gE = (1 + mpz(E) * N) % N2                                      # = g^E for g = 1 + N
        CTi = (gE * gmpy2.powmod(self.h1(T), N * self.sm_gamma[i], N2)) % N2
        t1 = time.perf_counter()
        exp = self.sm_h2[i] if self.variant == 'main' else self.sm_h2_inv[i]
        sigma_i = (self.H_att[i] * (self.nu ** self.zr(CTi))) ** self.zr(exp)
        t2 = time.perf_counter()
        if timing is not None:
            timing['sm_encrypt'] = t1 - t0
            timing['sm_auth'] = t2 - t1
        return CTi, sigma_i, T

    # ---- Data Aggregation (AG) ---------------------------------------------------------

    def ag_aggregate(self, reports, nonce, timing=None):
        n, N, N2 = self.n, self.N, self.N2
        T = reports[0][2]
        t0 = time.perf_counter()
        CT = mpz(1)
        for CTi, _, _ in reports:
            CT = (CT * CTi) % N2
        t1 = time.perf_counter()
        taus = self.prg(self.sk_prg, nonce)
        taus.append(self.h3(gmpy2.powmod(CT, N, N2), nonce))           # tau_n = h3(CT^N || nonce)
        t2 = time.perf_counter()
        if self.variant == 'main':
            sigma = reports[0][1] ** self.zr(taus[0])
            for i in range(1, n):
                sigma = sigma * (reports[i][1] ** self.zr(taus[i]))
            t3 = time.perf_counter()
            xi = self.beta[0] ** self.zr(taus[0] * reports[0][0])
            for i in range(1, n):
                xi = xi * (self.beta[i] ** self.zr(taus[i] * reports[i][0]))
        else:
            sigma = reports[0][1] ** self.zr(taus[0] * self.psi[0])
            for i in range(1, n):
                sigma = sigma * (reports[i][1] ** self.zr(taus[i] * self.psi[i]))
            t3 = time.perf_counter()
            xi = 0
            for i in range(n):
                xi = (xi + taus[i] * int(reports[i][0])) % self.p      # xi = sum tau_i CT_i
        t4 = time.perf_counter()
        if timing is not None:
            timing.update({'ag_combine_ct': t1 - t0, 'ag_tau': t2 - t1, 'ag_sigma': t3 - t2,
                           'ag_xi': t4 - t3})
        return CT, sigma, xi, T

    # ---- Verification and Decryption (CC) ------------------------------------------------

    def cc_verify(self, CT, sigma, xi, T, nonce, timing=None):
        """Integrity verification exactly as published: CT is not an input of the check."""
        n, N, N2 = self.n, self.N, self.N2
        t0 = time.perf_counter()
        taus = self.prg(self.sk_prg, nonce)
        taus.append(self.h3(gmpy2.powmod(self.h1(T), N * N * self.cc_gamma_prime, N2), nonce))
        t1 = time.perf_counter()
        lhs = pair(sigma, self.rho)
        if self.variant == 'main':
            rhs = pair(self.H_att[0] ** self.zr(taus[0]), self.beta[0])
            for i in range(1, n):
                rhs = rhs * pair(self.H_att[i] ** self.zr(taus[i]), self.beta[i])
            rhs = rhs * pair(self.nu, xi)
        else:
            comb = self.H_att[0] ** self.zr(taus[0])
            for i in range(1, n):
                comb = comb * (self.H_att[i] ** self.zr(taus[i]))
            comb = comb * (self.nu ** self.zr(xi))
            rhs = pair(comb, self.beta)
        ok = (lhs == rhs)
        t2 = time.perf_counter()
        if timing is not None:
            timing.update({'cc_tau': t1 - t0, 'cc_pairing_check': t2 - t1})
        return ok

    def cc_decrypt(self, CT, T, timing=None):
        k, N, N2 = self.k, self.N, self.N2
        t0 = time.perf_counter()
        W = (CT * gmpy2.powmod(self.h1(T), N * self.cc_gamma0, N2)) % N2
        Q = (W - 1) // N
        QM, M = [0] * k, [0] * k
        for j in range(k - 1, -1, -1):                                  # Algorithm 1
            QM[j] = int((Q - Q % self.omega[k + j]) // self.omega[k + j])
            Q = Q - self.omega[k + j] * QM[j]
        for j in range(k - 1, -1, -1):
            M[j] = int((Q - Q % self.omega[j]) // self.omega[j])
            Q = Q - self.omega[j] * M[j]
        avr = [M[j] / self.n for j in range(k)]
        var = [QM[j] / self.n - avr[j] ** 2 for j in range(k)]
        if timing is not None:
            timing['cc_decrypt'] = time.perf_counter() - t0
        return M, QM, avr, var

    # ---- message sizes (bytes) -------------------------------------------------------------

    def sizes(self):
        nb = (self.N.bit_length() + 7) // 8
        ct, g1, g2, zp, ts = 2 * nb, 32, 64, 32, 8                      # compressed BN254; 64-bit timestamp
        return {'sm_msg_B': ct + g1 + ts,                               # {CT_i, sigma_i, T}
                'ag_msg_B': ct + g1 + (g2 if self.variant == 'main' else zp) + ts,   # (CT, sigma, xi, T)
                'ct_B': ct}


# ---------------------------------------------------------------------------
# --check: correctness and verification behaviour
# ---------------------------------------------------------------------------

def check(paillier_bits):
    import random
    fails = 0

    def ok(c, msg):
        nonlocal fails
        print(("  PASS: " if c else "  FAIL: ") + msg)
        fails += (not c)

    for variant in ('main', 'extended'):
        for k, n in ((1, 8), (3, 6)):
            rng = random.Random(10 * k + n)
            s = VPMDA(n, k=k, eta=[2 ** 16 - 1] * k, paillier_bits=paillier_bits, variant=variant)
            s.setup()
            T, nonce = 1700000000, b'nonce-1'
            data = [[rng.randint(0, 2 ** 16 - 1) for _ in range(k)] for _ in range(n)]
            reps = [s.sm_report(i, data[i], T) for i in range(n)]
            CT, sig, xi, _ = s.ag_aggregate(reps, nonce)
            M, QM, _, _ = s.cc_decrypt(CT, T)
            trueM = [sum(d[j] for d in data) for j in range(k)]
            trueQ = [sum(d[j] ** 2 for d in data) for j in range(k)]
            print(f"{variant}, k = {k}, n = {n}:")
            ok(s.cc_verify(CT, sig, xi, T, nonce), "honest aggregate passes the integrity check")
            ok(M == trueM and QM == trueQ, "decryption recovers every sum and sum of squares (Algorithm 1)")

            bad = list(reps)
            bad[0] = (reps[0][0], reps[0][1] * s.H_att[0], T)
            CTb, sb, xb, _ = s.ag_aggregate(bad, nonce)
            ok(not s.cc_verify(CTb, sb, xb, T, nonce), "a tampered authenticator sigma_i is rejected")

            swap = list(reps)
            CT1 = (reps[0][0] * (1 + 5 * s.N)) % s.N2
            swap[0] = (CT1, reps[0][1], T)
            CTs, ss, xs, _ = s.ag_aggregate(swap, nonce)
            ok(not s.cc_verify(CTs, ss, xs, T, nonce),
               "a replaced ciphertext CT_i (AG aggregates it honestly) is rejected (paper's Game 1)")
            ok(not s.cc_verify(CT, sig, xi, T, b'nonce-2'), "a different nonce is rejected")

            delta = s.omega[0] * 1000
            CTf = (CT * (1 + delta * s.N)) % s.N2
            Mf, _, _, _ = s.cc_decrypt(CTf, T)
            acc = s.cc_verify(CTf, sig, xi, T, nonce)
            print(f"  NOTE: published verification with the aggregate CT replaced by CT*(1+N)^delta and the "
                  f"honest (sigma, xi): {'ACCEPTED' if acc else 'rejected'}; decrypts to "
                  f"{Mf[0]} instead of {trueM[0]} (CT is not an input of CC's check)")
    print("ALL PASSED" if not fails else f"{fails} FAILED")
    return fails


# ---------------------------------------------------------------------------
# --bench: timing sweep (same conventions as the CRVDA-AOE scripts)
# ---------------------------------------------------------------------------

N_SWEEP = [50, 100, 250, 500, 750, 1000]
N_TRIALS = {50: 10, 100: 10, 250: 10, 500: 5, 750: 3, 1000: 3}

STAGES = """Stage definitions (all times wall clock, time.perf_counter, single process, sequential)
  setup_ms            TTP Initialization (one-time; excluded from per-round figures)
  sm_encrypt_ms       one meter: CT_i                       (median over the n meters of the trial)
  sm_auth_ms          one meter: sigma_i                    (median over the n meters)
  sm_total_ms         one meter: CT_i + sigma_i             (median over the n meters)
  ag_combine_ct_ms    AG: CT = prod CT_i
  ag_tau_ms           AG: prg + tau_n = h3(CT^N || nonce)
  ag_sigma_ms         AG: aggregated authenticator sigma
  ag_xi_ms            AG: blind value xi
  ag_total_ms         AG: sum of the four
  cc_tau_ms           CC: prg + tau_n from h1(T)^{N^2 gamma'}
  cc_pairing_check_ms CC: integrity verification equation (main n+2 pairings; extended 2)
  cc_verify_ms        CC: cc_tau + cc_pairing_check
  cc_decrypt_ms       CC: W, Q and Algorithm 1
  cc_total_ms         CC: verify + decrypt
  sm_msg_B, ag_msg_B  bytes SM->AG {CT_i, sigma_i, T} and AG->CC (CT, sigma, xi, T);
                      compressed BN254 (G1 32 B, G2 64 B, Z_p 32 B), CT 2|N| bits, T 8 B"""


def q(vals, p):
    s = sorted(vals)
    if len(s) == 1:
        return s[0]
    pos = (len(s) - 1) * p
    lo = math.floor(pos)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def bench(args):
    import random
    out = args.out or f"vpmda_results_{args.variant}"
    os.makedirs(out, exist_ok=True)
    Ns = args.n or N_SWEEP
    data = None
    
    eta = [args.eta] * args.k

    with open(os.path.join(out, 'vpmda_env.txt'), 'w') as f:
        f.write(f"scheme: VPMDA ({args.variant}), Zhang et al., IEEE TDSC 2022 -- re-implementation\n"
                f"pairing group: BN254 (Charm/PBC), asymmetric adaptation of the paper's symmetric pairing\n"
                f"Paillier: |N| = {args.paillier_bits} bits (gmpy2/GMP)\n"
                f"k = {args.k} data type(s), eta = {args.eta}\n"
                f"n = {Ns}, trials = {args.trials or N_TRIALS}, warm-up = 1 round (n = 8)\n"
                f"readings: {args.data or 'uniform random in [0, eta]'}\n"
                f"python {sys.version.split()[0]}, gmpy2 {gmpy2.version()}, {platform.platform()}, "
                f"{platform.machine()}\n\n{STAGES}\n")

    w = VPMDA(8, k=args.k, eta=eta, paillier_bits=args.paillier_bits, variant=args.variant)
    w.setup()
    reps = [w.sm_report(i, [1] * args.k, 1) for i in range(8)]
    c, s_, x, _ = w.ag_aggregate(reps, b'warm')
    w.cc_verify(c, s_, x, 1, b'warm')
    w.cc_decrypt(c, 1)

    rows = []
    rng = random.Random(args.seed)
    for n in Ns:
        trials = args.trials or N_TRIALS.get(n, 3)
        for tr in range(trials):
            s = VPMDA(n, k=args.k, eta=eta, paillier_bits=args.paillier_bits, variant=args.variant)
            t0 = time.perf_counter()
            s.setup()
            setup_s = time.perf_counter() - t0
            if data is not None and args.k == 1:
                vals = [data[i % len(data)] for i in range(n)]
                if max(vals) > args.eta:
                    raise SystemExit(f"a reading exceeds eta = {args.eta}; raise --eta")
                msgs = [[v] for v in vals]
            else:
                msgs = [[rng.randint(0, args.eta) for _ in range(args.k)] for _ in range(n)]
            T, nonce = 1700000000 + tr, f"nonce-{n}-{tr}".encode()

            sm_enc, sm_auth, reps = [], [], []
            for i in range(n):
                tm = {}
                reps.append(s.sm_report(i, msgs[i], T, tm))
                sm_enc.append(tm['sm_encrypt'])
                sm_auth.append(tm['sm_auth'])
            ta = {}
            CT, sig, xi, _ = s.ag_aggregate(reps, nonce, ta)
            tc = {}
            okv = s.cc_verify(CT, sig, xi, T, nonce, tc)
            M, QM, _, _ = s.cc_decrypt(CT, T, tc)
            trueM = [sum(m[j] for m in msgs) for j in range(args.k)]
            trueQ = [sum(m[j] ** 2 for m in msgs) for j in range(args.k)]
            if not okv or M != trueM or QM != trueQ:
                raise AssertionError(f"round failed at n={n}: verify={okv}, M={M} vs {trueM}")

            ms = lambda v: v * 1000.0
            r = {'n': n, 'trial': tr, 'variant': args.variant, 'k': args.k, 'paillier_bits': args.paillier_bits,
                 'setup_ms': ms(setup_s),
                 'sm_encrypt_ms': ms(q(sm_enc, .5)), 'sm_auth_ms': ms(q(sm_auth, .5)),
                 'sm_total_ms': ms(q([a + b for a, b in zip(sm_enc, sm_auth)], .5)),
                 'all_sm_serial_ms': ms(sum(sm_enc) + sum(sm_auth))}
            r.update({f'{k_}_ms': ms(v) for k_, v in ta.items()})
            r['ag_total_ms'] = ms(sum(ta.values()))
            r['cc_tau_ms'] = ms(tc['cc_tau'])
            r['cc_pairing_check_ms'] = ms(tc['cc_pairing_check'])
            r['cc_verify_ms'] = ms(tc['cc_tau'] + tc['cc_pairing_check'])
            r['cc_decrypt_ms'] = ms(tc['cc_decrypt'])
            r['cc_total_ms'] = r['cc_verify_ms'] + r['cc_decrypt_ms']
            r.update(s.sizes())
            rows.append(r)
            print(f"n={n:5d} trial {tr + 1}/{trials}: SM {r['sm_total_ms']:.2f} ms/meter | "
                  f"AG {r['ag_total_ms'] / 1000:.2f} s | CC verify {r['cc_verify_ms'] / 1000:.3f} s, "
                  f"decrypt {r['cc_decrypt_ms']:.2f} ms")
        with open(os.path.join(out, 'vpmda_trials.csv'), 'w', newline='') as f:
            wr = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            wr.writeheader()
            wr.writerows(rows)

    summ = []
    for n in Ns:
        rs = [r for r in rows if r['n'] == n]
        srow = {'n': n, 'trials': len(rs), 'variant': args.variant, 'k': args.k,
                'paillier_bits': args.paillier_bits}
        for key in rs[0]:
            if key in srow or key == 'trial':
                continue
            vals = [float(r[key]) for r in rs]
            srow[f'{key}_median'], srow[f'{key}_q1'], srow[f'{key}_q3'] = q(vals, .5), q(vals, .25), q(vals, .75)
        summ.append(srow)
    with open(os.path.join(out, 'vpmda_summary.csv'), 'w', newline='') as f:
        wr = csv.DictWriter(f, fieldnames=list(summ[0].keys()))
        wr.writeheader()
        wr.writerows(summ)
    print(f"Wrote vpmda_trials.csv, vpmda_summary.csv, vpmda_env.txt in {out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--bench', action='store_true')
    ap.add_argument('--variant', choices=('main', 'extended'), default='extended')
    ap.add_argument('--n', type=int, nargs='+', default=None)
    ap.add_argument('--trials', type=int, default=None)
    ap.add_argument('--k', type=int, default=1)
    ap.add_argument('--eta', type=int, default=2 ** 16 - 1, help='upper bound of each reading (default 65535)')
    ap.add_argument('--paillier-bits', type=int, default=2048)
    ap.add_argument('--data', default=None)
    ap.add_argument('--column', type=int, default=0)
    ap.add_argument('--no-header', action='store_true')
    ap.add_argument('--decimals', type=int, default=3)
    ap.add_argument('--seed', type=int, default=1234)
    ap.add_argument('--out', default=None)
    a = ap.parse_args()
    if a.check:
        return 1 if check(a.paillier_bits) else 0
    if a.bench:
        bench(a)
        return 0
    ap.print_help()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())