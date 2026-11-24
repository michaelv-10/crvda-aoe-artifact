"""
lvp2da.py -- implementation of LV-P2DA, following the published scheme definition
=====================================================================================

"Lightweight Verifiable Privacy-Preserving Data Aggregation for Smart Grids"

Disclosed adaptations (the only departures from the paper)
  * Curve: secp224r1 (NIST P-224, ~112-bit security) by default -- the closest
    standard curve at or above BN254 (~100-bit) used by CRVDA-AOE, and the same
    level as our 2048-bit-Paillier baselines. --curve secp256k1 / prime256v1 for
    ~128-bit. The paper used the 160-bit JPBC Type D d159 curve (~80-bit).
  * Recovering M' from M = M'P: the paper suggests Pollard's lambda; we use
    baby-step giant-step over [0, n(2^L - 1)] -- the SAME bounded discrete-log
    routine as CRVDA-AOE -- with the table built once (one-time cost, reported
    separately).
  * Batch verification uses l = 5 (the paper's value) by default. Note that the
    small-exponent test then accepts a coordinated pair of invalid signatures
    with probability 2^-l (shown by --check); --batch-l raises it. Single
    verification is also available (--verify single).
  * Freshness: t must be within --window seconds of the BS clock (the paper
    assumes synchronised clocks; the window value is ours).
  * Hashes H1, H2, H3: SHA-256 over length-prefixed, domain-separated encodings,
    reduced mod q (0 mapped to 1, so outputs are in Z*_q). Randomness: secrets.

Security model of the published scheme (for the comparison table)
  The base station is honest-but-curious: the ESP accepts whatever (R_bs, C_bs)
  the BS signs, so aggregation integrity relies on an honest BS; readings are not
  range-checked, so a meter can encrypt any value. --check shows both.

Usage
  python3 lvp2da.py --check
  caffeinate -i python3 lvp2da.py --bench --data readings.xlsx | tee lvp2da.log
  python3 lvp2da.py --bench --curve secp256k1 --verify single --n 50 100 --trials 3

Outputs (in --out, default lvp2da_results_<curve>_<verify>)
  lvp2da_trials.csv, lvp2da_summary.csv (median, q1, q3), lvp2da_env.txt
"""

import argparse
import csv
import hashlib
import math
import os
import platform
import secrets
import sys
import time

from charm.toolbox.ecgroup import ECGroup, ZR, G
import charm.toolbox.eccurve as eccurve


def _enc(x):
    if isinstance(x, bytes):
        b = x
    elif isinstance(x, str):
        b = x.encode()
    elif isinstance(x, int):
        b = str(x).encode()
    else:
        raise TypeError(type(x))
    return len(b).to_bytes(4, 'big') + b


class LVP2DA:
    def __init__(self, curve='secp224r1', batch_l=5, window=300):
        self.curve_name = curve
        self.group = ECGroup(getattr(eccurve, curve))
        self.q = int(self.group.order())
        self.batch_l = batch_l
        self.window = window
        self.zero = self.group.init(ZR, 0)

    # ---- helpers ------------------------------------------------------------------

    def ser(self, e):
        return self.group.serialize(e)

    def Hi(self, i, *parts):
        """H_i: {0,1}* -> Z*_q"""
        h = hashlib.sha256(b'LV-P2DA-H' + str(i).encode())
        for p in parts:
            h.update(_enc(self.ser(p) if not isinstance(p, (bytes, str, int)) else p))
        v = int.from_bytes(h.digest(), 'big') % self.q
        return self.group.init(ZR, v if v else 1)

    def rand_zq(self):
        return self.group.init(ZR, secrets.randbelow(self.q - 1) + 1)

    # ---- A. Initialization and Registration ----------------------------------------------

    def system_setup(self):
        self.P = self.group.random(G)
        self.s = self.rand_zq()                       # msk
        self.Ppub = self.P ** self.s
        self.ent = {}

    def key_extract(self, ID):
        x = self.rand_zq()
        self.ent[ID] = {'x': x, 'pk': self.P ** x}
        return self.ent[ID]['pk']

    def certification(self, ID):
        e_ = self.ent[ID]
        d = self.rand_zq()
        D = self.P ** d
        h1 = self.Hi(1, ID, e_['pk'], D)
        e_['D'], e_['e'] = D, d + self.s * h1
        assert self.P ** e_['e'] == D * (self.Ppub ** h1)          # e P = D + h1 P_pub
        return D, e_['e']

    def register(self, n):
        """KGC + all entities: n meters 'sm1'..'smn', 'bs', 'esp'; W prestored in every SM."""
        for ID in [f'sm{i}' for i in range(1, n + 1)] + ['bs', 'esp']:
            self.key_extract(ID)
            self.certification(ID)
        esp = self.ent['esp']
        h1 = self.Hi(1, 'esp', esp['pk'], esp['D'])
        self.W = esp['D'] * (self.Ppub ** h1) * esp['pk']

    # ---- B. Data Transmission and Aggregation ----------------------------------------------

    def sm_encryption(self, m_int):
        m = self.P ** self.group.init(ZR, m_int)       # m_sm = m' P
        r = self.rand_zq()
        R = self.P ** r
        C = (self.W ** r) * m                          # C = rW + m_sm
        return R, C

    def sign(self, ID, R, C, t):
        e_ = self.ent[ID]
        u = self.rand_zq()
        U = self.P ** u
        h2 = self.Hi(2, R, C, e_['pk'], U)
        h3 = self.Hi(3, self.Ppub, U, h2, t)
        v = e_['e'] + e_['x'] * h2 + u * h3
        return (e_['D'], U, v)

    def sm_report(self, i, m_int, t, timing=None):
        ID = f'sm{i}'
        t0 = time.perf_counter()
        R, C = self.sm_encryption(m_int)
        t1 = time.perf_counter()
        sigma = self.sign(ID, R, C, t)
        t2 = time.perf_counter()
        if timing is not None:
            timing['sm_encrypt'], timing['sm_sign'] = t1 - t0, t2 - t1
        return (ID, R, C, sigma, t)

    def fresh(self, t, now):
        return abs(now - t) <= self.window

    def _hashes(self, ID, pk, R, C, sigma, t):
        D, U, v = sigma
        h1 = self.Hi(1, ID, pk, D)
        h2 = self.Hi(2, R, C, pk, U)
        h3 = self.Hi(3, self.Ppub, U, h2, t)
        return h1, h2, h3

    def verify_single(self, msg, now):
        ID, R, C, sigma, t = msg
        if not self.fresh(t, now):
            return False
        pk = self.ent[ID]['pk']                        # public key of the claimed identity
        D, U, v = sigma
        h1, h2, h3 = self._hashes(ID, pk, R, C, sigma, t)
        return self.P ** v == D * (self.Ppub ** h1) * (pk ** h2) * (U ** h3)

    def verify_batch(self, msgs, now):
        if not all(self.fresh(m[4], now) for m in msgs):
            return False
        v_sum, h1_sum = self.zero, self.zero
        acc = None
        for ID, R, C, sigma, t in msgs:
            pk = self.ent[ID]['pk']
            D, U, v = sigma
            h1, h2, h3 = self._hashes(ID, pk, R, C, sigma, t)
            si = self.group.init(ZR, secrets.randbelow(2 ** self.batch_l) + 1)    # s_i in [1, 2^l]
            v_sum = v_sum + si * v
            h1_sum = h1_sum + si * h1
            term = (D ** si) * (pk ** (si * h2)) * (U ** (si * h3))             # one scalar mult each
            acc = term if acc is None else acc * term
        return self.P ** v_sum == acc * (self.Ppub ** h1_sum)

    def bs_aggsig(self, msgs, t_bs):
        Rbs, Cbs = msgs[0][1], msgs[0][2]
        for m in msgs[1:]:
            Rbs, Cbs = Rbs * m[1], Cbs * m[2]
        return ('bs', Rbs, Cbs, self.sign('bs', Rbs, Cbs, t_bs), t_bs)

    # ---- C. Data Verification and Decryption ----------------------------------------------

    def build_dlog_table(self, upper_bound):
        m = math.isqrt(max(upper_bound, 1)) + 1
        table, cur = {}, self.P ** self.zero
        for j in range(m):
            if j:
                cur = cur * self.P
            table[self.ser(cur)] = j
        self._tab, self._m, self._ub = table, m, upper_bound
        self._giant = (self.P ** self.group.init(ZR, m)) ** (self.zero - self.group.init(ZR, 1))

    def esp_decryption(self, Rbs, Cbs):
        esp = self.ent['esp']
        M = Cbs * (Rbs ** (self.zero - (esp['e'] + esp['x'])))     # M = C_bs - (e + x) R_bs
        cur = M
        for i in range(self._m + 1):
            j = self._tab.get(self.ser(cur))
            if j is not None and i * self._m + j <= self._ub:
                return i * self._m + j
            cur = cur * self._giant
        raise ValueError("aggregate outside [0, n(2^L - 1)]")

    # ---- sizes (bytes): |ID| = |t| = 4 B as in the paper's Table IV ------------------

    def sizes(self):
        qb = (self.q.bit_length() + 7) // 8
        g = qb + 1                                     # compressed point
        one = 4 + 4 + 4 * g + qb                       # ID, R, C, D, U, v, t
        return {'sm_msg_B': one, 'bs_msg_B': one, 'point_B': g, 'scalar_B': qb}


# ---------------------------------------------------------------------------
# --check
# ---------------------------------------------------------------------------

def check(curve, batch_l):
    fails = 0

    def ok(c, msg):
        nonlocal fails
        print(("  PASS: " if c else "  FAIL: ") + msg)
        fails += (not c)

    s = LVP2DA(curve, batch_l)
    s.system_setup()
    n, L = 8, 16
    s.register(n)
    s.build_dlog_table(n * (2 ** L - 1))
    now = int(time.time())
    xs = [secrets.randbelow(2 ** L) for _ in range(n)]
    xs[0] = 2 ** L - 1
    msgs = [s.sm_report(i + 1, xs[i], now) for i in range(n)]
    print(f"LV-P2DA on {curve}, n = {n}, batch l = {batch_l}:")
    for ID in s.ent:
        e_ = s.ent[ID]
        ok(s.P ** e_['e'] == e_['D'] * (s.Ppub ** s.Hi(1, ID, e_['pk'], e_['D'])),
           f"certificate of {ID} is valid") if ID in ('sm1', 'bs', 'esp') else None
    ok(all(s.verify_single(m, now) for m in msgs), "every meter signature passes single verification")
    ok(s.verify_batch(msgs, now), "batch verification accepts the honest batch")
    agg = s.bs_aggsig(msgs, now)
    ok(s.verify_single(agg, now), "ESP verifies the base station's signature")
    ok(s.esp_decryption(agg[1], agg[2]) == sum(xs), f"ESP recovers the exact sum {sum(xs)}")

    ID, R, C, sig, t = msgs[1]
    bad = (ID, R, C * s.P, sig, t)
    ok(not s.verify_single(bad, now), "altered ciphertext C is rejected (single)")
    ok(not s.verify_batch(msgs[:1] + [bad] + msgs[2:], now), "altered ciphertext C is rejected (batch)")
    D, U, v = sig
    ok(not s.verify_single((ID, R, C, (D, U, v + s.group.init(ZR, 1)), t), now), "altered signature is rejected")
    ok(not s.verify_single(('sm3', R, C, sig, t), now), "a report presented under another meter's identity is rejected")
    ok(not s.verify_single(msgs[2][:4] + (now - 10 * s.window,), now), "a stale timestamp is rejected")
    a = agg
    ok(not s.verify_single((a[0], a[1], a[2] * s.P, a[3], a[4]), now), "an altered aggregate (R_bs, C_bs) is rejected by the ESP")

    # coordinated invalid pair: v1 + delta, v2 - delta passes iff s_1 = s_2 (probability 2^-l)
    trials, acc = 2000, 0
    pair_ = msgs[:2]
    for _ in range(trials):
        dlt = s.rand_zq()
        (I1, R1, C1, (D1, U1, v1), t1), (I2, R2, C2, (D2, U2, v2), t2) = pair_
        forged = [(I1, R1, C1, (D1, U1, v1 + dlt), t1), (I2, R2, C2, (D2, U2, v2 - dlt), t2)]
        acc += s.verify_batch(forged, now)
    print(f"  NOTE: a coordinated pair of INVALID signatures passed batch verification in {acc}/{trials} "
          f"trials ({100 * acc / trials:.1f}%; expected 2^-{batch_l} = {100 / 2 ** batch_l:.1f}%). "
          f"Single verification rejects both.")

    fake = s.bs_aggsig([s.sm_report(i + 1, 0, now) for i in range(n)], now)
    fake = ('bs', fake[1], fake[2] * (s.P ** s.group.init(ZR, 500)), None, now)
    fake = fake[:3] + (s.sign('bs', fake[1], fake[2], now), now)
    print(f"  NOTE: a dishonest base station can sign an aggregate of its choice: ESP verification "
          f"{'ACCEPTS' if s.verify_single(fake, now) else 'rejects'} it and decrypts "
          f"{s.esp_decryption(fake[1], fake[2])} (true sum 0) -- the paper assumes an honest-but-curious BS.")
    m_big = s.sm_report(1, 10 ** 6, now)
    print(f"  NOTE: a meter can encrypt an out-of-range reading (10^6 > 2^{L}-1): its report "
          f"{'passes' if s.verify_single(m_big, now) else 'fails'} verification (no range proof in the scheme).")
    print("ALL PASSED" if not fails else f"{fails} FAILED")
    return fails


# ---------------------------------------------------------------------------
# --bench
# ---------------------------------------------------------------------------

N_SWEEP = [50, 100, 250, 500, 750, 1000]
N_TRIALS = {50: 10, 100: 10, 250: 10, 500: 5, 750: 3, 1000: 3}

STAGES = """Stage definitions (wall clock, time.perf_counter, single process, sequential)
  setup_ms            SystemSetup + KeyExtract/Certification of n meters, BS, ESP (one-time)
  dlog_table_ms       baby-step table for [0, n(2^L - 1)] (one-time)
  sm_encrypt_ms       one meter: SM-Encryption           (median over the n meters)
  sm_sign_ms          one meter: SM-Sign                 (median over the n meters)
  sm_total_ms         one meter: encryption + signature  (median over the n meters)
  bs_verify_ms        BS-Verification of all n reports (batch or single, see verify)
  bs_aggsig_ms        BS-AggSig: R_bs, C_bs and the BS signature
  bs_total_ms         bs_verify + bs_aggsig
  esp_verify_ms       ESP-Verification (single verification of sigma_bs)
  esp_decrypt_ms      ESP-Decryption incl. the bounded discrete log
  esp_total_ms        esp_verify + esp_decrypt
  sm_msg_B, bs_msg_B  ID + R + C + sigma (D, U, v) + t, |ID| = |t| = 4 B, compressed points"""


def q(vals, p):
    s = sorted(vals)
    if len(s) == 1:
        return s[0]
    pos = (len(s) - 1) * p
    lo = math.floor(pos)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def bench(a):
    out = a.out or f"lvp2da_results_{a.curve}_{a.verify}"
    os.makedirs(out, exist_ok=True)
    Ns = a.n or N_SWEEP
    data = None
    
    maxv = 2 ** a.L - 1
    with open(os.path.join(out, 'lvp2da_env.txt'), 'w') as f:
        f.write(f"scheme: LV-P2DA, Zhu et al., IEEE IoT-J 2024 -- re-implementation\n"
                f"curve: {a.curve} (Charm ECGroup / OpenSSL), verification: {a.verify}, batch l = {a.batch_l}\n"
                f"L = {a.L}, n = {Ns}, trials = {a.trials or N_TRIALS}, warm-up = 1 round (n = 8)\n"
                f"readings: {a.data or 'uniform random in [0, 2^L)'}\n"
                f"python {sys.version.split()[0]}, {platform.platform()}, {platform.machine()}\n\n{STAGES}\n")

    w = LVP2DA(a.curve, a.batch_l)
    w.system_setup()
    w.register(8)
    w.build_dlog_table(8 * maxv)
    now = int(time.time())
    ms_ = [w.sm_report(i + 1, 1, now) for i in range(8)]
    w.verify_batch(ms_, now)
    g = w.bs_aggsig(ms_, now)
    w.verify_single(g, now)
    w.esp_decryption(g[1], g[2])

    rows = []
    for n in Ns:
        trials = a.trials or N_TRIALS.get(n, 3)
        for tr in range(trials):
            s = LVP2DA(a.curve, a.batch_l)
            t0 = time.perf_counter()
            s.system_setup()
            s.register(n)
            setup = time.perf_counter() - t0
            t0 = time.perf_counter()
            s.build_dlog_table(n * maxv)
            tab = time.perf_counter() - t0
            xs = ([data[i % len(data)] for i in range(n)] if data is not None
                  else [secrets.randbelow(maxv + 1) for _ in range(n)])
            if max(xs) > maxv:
                raise SystemExit(f"a reading exceeds 2^{a.L} - 1; raise --L")
            now = int(time.time())
            enc, sig, msgs = [], [], []
            for i in range(n):
                tm = {}
                msgs.append(s.sm_report(i + 1, xs[i], now, tm))
                enc.append(tm['sm_encrypt'])
                sig.append(tm['sm_sign'])
            t0 = time.perf_counter()
            okb = (s.verify_batch(msgs, now) if a.verify == 'batch'
                   else all(s.verify_single(m, now) for m in msgs))
            t1 = time.perf_counter()
            agg = s.bs_aggsig(msgs, now)
            t2 = time.perf_counter()
            oke = s.verify_single(agg, now)
            t3 = time.perf_counter()
            total = s.esp_decryption(agg[1], agg[2])
            t4 = time.perf_counter()
            if not (okb and oke and total == sum(xs)):
                raise AssertionError(f"round failed at n={n}: bs={okb} esp={oke} sum={total} vs {sum(xs)}")
            ms = lambda v: v * 1000.0
            r = {'n': n, 'trial': tr, 'curve': a.curve, 'verify': a.verify, 'batch_l': a.batch_l,
                 'setup_ms': ms(setup), 'dlog_table_ms': ms(tab),
                 'sm_encrypt_ms': ms(q(enc, .5)), 'sm_sign_ms': ms(q(sig, .5)),
                 'sm_total_ms': ms(q([x + y for x, y in zip(enc, sig)], .5)),
                 'all_sm_serial_ms': ms(sum(enc) + sum(sig)),
                 'bs_verify_ms': ms(t1 - t0), 'bs_aggsig_ms': ms(t2 - t1), 'bs_total_ms': ms(t2 - t0),
                 'esp_verify_ms': ms(t3 - t2), 'esp_decrypt_ms': ms(t4 - t3), 'esp_total_ms': ms(t4 - t2)}
            r.update(s.sizes())
            rows.append(r)
            print(f"n={n:5d} trial {tr + 1}/{trials}: SM {r['sm_total_ms']:.2f} ms/meter | "
                  f"BS {r['bs_total_ms'] / 1000:.3f} s | ESP {r['esp_total_ms']:.2f} ms")
        with open(os.path.join(out, 'lvp2da_trials.csv'), 'w', newline='') as f:
            wr = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            wr.writeheader()
            wr.writerows(rows)

    summ = []
    for n in Ns:
        rs = [r for r in rows if r['n'] == n]
        sr = {'n': n, 'trials': len(rs), 'curve': a.curve, 'verify': a.verify, 'batch_l': a.batch_l}
        for k in rs[0]:
            if k in sr or k == 'trial':
                continue
            v = [float(r[k]) for r in rs]
            sr[f'{k}_median'], sr[f'{k}_q1'], sr[f'{k}_q3'] = q(v, .5), q(v, .25), q(v, .75)
        summ.append(sr)
    with open(os.path.join(out, 'lvp2da_summary.csv'), 'w', newline='') as f:
        wr = csv.DictWriter(f, fieldnames=list(summ[0].keys()))
        wr.writeheader()
        wr.writerows(summ)
    print(f"Wrote lvp2da_trials.csv, lvp2da_summary.csv, lvp2da_env.txt in {out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--bench', action='store_true')
    ap.add_argument('--curve', default='secp224r1', help='secp224r1 (default, ~112-bit), secp256k1, prime256v1')
    ap.add_argument('--verify', choices=('batch', 'single'), default='batch')
    ap.add_argument('--batch-l', type=int, default=5, help="randomizer bits for batch verification (paper: 5)")
    ap.add_argument('--L', type=int, default=16)
    ap.add_argument('--n', type=int, nargs='+', default=None)
    ap.add_argument('--trials', type=int, default=None)
    ap.add_argument('--data', default=None)
    ap.add_argument('--column', type=int, default=0)
    ap.add_argument('--no-header', action='store_true')
    ap.add_argument('--decimals', type=int, default=3)
    ap.add_argument('--out', default=None)
    a = ap.parse_args()
    if not hasattr(eccurve, a.curve):
        raise SystemExit(f"curve {a.curve} is not in this Charm build; try secp256k1 or prime256v1")
    if a.check:
        return 1 if check(a.curve, a.batch_l) else 0
    if a.bench:
        bench(a)
        return 0
    ap.print_help()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())