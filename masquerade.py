"""
masquerade.py -- implementation of (base) Masquerade, following the published protocol
=========================================================================================

"Masquerade: Verifiable Multi-Party Aggregation with Secure Multiplicative Commitments".
Base Masquerade only (Sec. 5.1, Figure 2, Appendix A.1 Protocol 1); zk-Masquerade
(range / set-membership ZKPs, threshold Paillier) is NOT implemented.

Disclosed implementation choices
  * Parameters: |N| = 2048 bits (N^2 = 4096 bits), the paper's own setting
    (Sec. 3.3.1 / 8.1), ~112-bit security -- at least as strong as BN254 (~100-bit).
  * Key generation uses safe primes p = 2p'+1, q = 2q'+1 so that a maximal-order
    g_m (order N lambda) can be generated AND verified (a^{N lambda / f} != 1 for
    every prime f | N lambda). The analyst generates one key pair per run (as in the
    paper); its time is reported once and excluded from per-round figures.
  * The analyst obtains the Protocol 1 witness rho_0 from ct_0 with the secret key
    (rho_0 = (ct_0 mod N)^{N^-1 mod lambda} mod N). Figure 2, line 7 lists "rho'"
    among the published values; we publish the proof (a, z), not the prover's
    nonce rho', since publishing rho' would reveal the witness.
  * Enc(m, rho) is computed as (1 + mN) rho^N mod N^2 (= g^m rho^N for g = N + 1).
  * Randomness from `secrets`; SHA-256 inputs are fixed-length big-endian encodings.

Threat model of base Masquerade (for the comparison table; shown by --check)
  Protects against a malicious curator (commitments) and a semi-honest analyst
  (decryption proof). Participants are trusted to submit valid inputs: there are
  no range proofs, so an out-of-range or "negative" input is aggregated.

Usage
  python3 masquerade.py --check
  caffeinate -i python3 masquerade.py --bench --data readings.xlsx | tee masquerade.log
  python3 masquerade.py --bench --n 50 100 --trials 3 --modulus-bits 3072

Outputs (in --out, default masquerade_results)
  masquerade_trials.csv    one row per (n, trial), unrounded
  masquerade_summary.csv   per n: mean, std, median, q1, q3 of every column
  masquerade_env.txt       parameters, key-generation time, platform, stage definitions
"""

import argparse
import csv
import hashlib
import math
import os
import platform
import secrets
import statistics
import sys
import time

import gmpy2
from gmpy2 import mpz


# ---------------------------------------------------------------------------
# primes and keys
# ---------------------------------------------------------------------------

def _prime(bits):
    while True:
        p = gmpy2.next_prime(mpz(secrets.randbits(bits)) | (mpz(1) << (bits - 1)) | 1)
        if p.bit_length() == bits:
            return p


def _safe_prime(bits):
    """p = 2p' + 1 with p' prime and |p| = bits."""
    while True:
        pp = _prime(bits - 1)
        p = 2 * pp + 1
        if gmpy2.is_prime(p, 40):
            return p, pp


class Keys:
    """Analyst's Key-Generation output: public (N, N2, e, g_m), secret (lam, mu, d)."""

    def __init__(self, modulus_bits):
        half = modulus_bits // 2
        while True:
            p, pp = _safe_prime(half)
            q, qq = _safe_prime(half)
            if p != q and pp != qq:
                break
        N = p * q
        self.N, self.N2 = N, N * N
        self.lam = 2 * pp * qq                       # lcm(p-1, q-1) for safe primes
        self.mu = gmpy2.invert(self.lam, N)          # L(g^lam) = lam for g = N + 1
        self.d = gmpy2.invert(N, self.lam)           # for the Protocol 1 witness
        # random prime e > N^2 (then gcd(e, phi(N^2)) = 1 automatically)
        while True:
            e = gmpy2.next_prime(self.N2 + mpz(secrets.randbits(self.N2.bit_length())))
            if e > self.N2:
                self.e = e
                break
        # g_m of maximal order N*lam in Z*_{N^2}
        order = N * self.lam
        factors = [2, pp, qq, p, q]
        while True:
            a = mpz(secrets.randbelow(int(self.N2) - 2) + 2)
            if gmpy2.gcd(a, self.N2) != 1:
                continue
            if all(gmpy2.powmod(a, order // f, self.N2) != 1 for f in factors):
                self.g_m = a
                break


def rand_unit(mod):
    while True:
        v = mpz(secrets.randbelow(int(mod) - 1) + 1)
        if gmpy2.gcd(v, mod) == 1:
            return v


def b(x, nbytes):
    return int(x).to_bytes(nbytes, 'big')


# ---------------------------------------------------------------------------
# Paillier, commitment, Protocol 1
# ---------------------------------------------------------------------------

def enc(K, m, rho):
    return ((1 + mpz(m) * K.N) * gmpy2.powmod(rho, K.N, K.N2)) % K.N2


def dec(K, c):
    return int(((gmpy2.powmod(c, K.lam, K.N2) - 1) // K.N) * K.mu % K.N)


def com(K, m, r):                                     # Eq. 3: Com(m, r) = m^e g_m^r mod N^2
    return (gmpy2.powmod(m, K.e, K.N2) * gmpy2.powmod(K.g_m, r, K.N2)) % K.N2


def fs_hash(K, c, a):                                 # h = SHA256(N, c, a)
    nb = (K.N2.bit_length() + 7) // 8
    return mpz(int.from_bytes(hashlib.sha256(b(K.N, nb) + b(c, nb) + b(a, nb)).digest(), 'big'))


def prove_zero(K, c, rho0):                           # Protocol 1, prover
    rp = rand_unit(K.N)
    a = gmpy2.powmod(rp, K.N, K.N2)
    h = fs_hash(K, c, a)
    z = (rp * gmpy2.powmod(rho0, h, K.N2)) % K.N2
    return a, z


def verify_zero(K, c, proof):                         # Protocol 1, verifier
    a, z = proof
    h = fs_hash(K, c, a)
    return gmpy2.powmod(z, K.N, K.N2) == (a * gmpy2.powmod(c, h, K.N2)) % K.N2


# ---------------------------------------------------------------------------
# Figure 2 algorithms
# ---------------------------------------------------------------------------

def participant(K, m, timing=None):
    t0 = time.perf_counter()
    ct = enc(K, m, rand_unit(K.N2))
    t1 = time.perf_counter()
    r = rand_unit(K.N2)
    c = com(K, ct, r)
    t2 = time.perf_counter()
    if timing is not None:
        timing['enc'], timing['commit'] = t1 - t0, t2 - t1
    return c, (ct, r)                                 # c -> ledger; (ct, r) -> curator


def curator(K, ledger_c, private, timing=None):
    t0 = time.perf_counter()
    for c, (ct, r) in zip(ledger_c, private):
        if com(K, ct, r) != c:
            raise ValueError("commitment does not open: participant rejected")
    t1 = time.perf_counter()
    ct_sum, r_sum = mpz(1), mpz(0)
    for ct, r in private:
        ct_sum = (ct_sum * ct) % K.N2
        r_sum += r
    t2 = time.perf_counter()
    if timing is not None:
        timing['cur_verify'], timing['cur_aggregate'] = t1 - t0, t2 - t1
    return ct_sum, r_sum


def _commit_product(K, ledger_c):
    prod = mpz(1)
    for c in ledger_c:
        prod = (prod * c) % K.N2
    return prod


def analyst(K, ledger_c, ct_sum, r_sum, timing=None):
    t0 = time.perf_counter()
    if _commit_product(K, ledger_c) != com(K, ct_sum, r_sum):
        raise ValueError("audit failed: commitments do not open to ct_sum")
    t1 = time.perf_counter()
    s = dec(K, ct_sum)
    t2 = time.perf_counter()
    rho = rand_unit(K.N2)
    ct_p = enc(K, s, rho)
    ct0 = (ct_sum * gmpy2.invert(ct_p, K.N2)) % K.N2
    rho0 = gmpy2.powmod(ct0 % K.N, K.d, K.N)          # witness: ct0 = rho0^N mod N^2
    pi0 = prove_zero(K, ct0, rho0)
    t3 = time.perf_counter()
    if timing is not None:
        timing['ana_audit'], timing['ana_decrypt'], timing['ana_prove'] = t1 - t0, t2 - t1, t3 - t2
    return {'sum': s, 'ct0': ct0, 'ct_p': ct_p, 'rho': rho, 'pi0': pi0}


def auditor(K, ledger_c, ct_sum, r_sum, pub, timing=None):
    t0 = time.perf_counter()
    ok = _commit_product(K, ledger_c) == com(K, ct_sum, r_sum)
    t1 = time.perf_counter()
    ok = ok and enc(K, pub['sum'], pub['rho']) == pub['ct_p']
    ok = ok and pub['ct0'] == (ct_sum * gmpy2.invert(pub['ct_p'], K.N2)) % K.N2
    ok = ok and verify_zero(K, pub['ct0'], pub['pi0'])
    t2 = time.perf_counter()
    if timing is not None:
        timing['aud_commits'], timing['aud_decryption'] = t1 - t0, t2 - t1
    return ok


def sizes(K, n):
    c = (K.N2.bit_length() + 7) // 8                  # element of Z_{N^2}
    rsum = (K.N2.bit_length() + math.ceil(math.log2(max(n, 2))) + 7) // 8
    return {'participant_to_curator_B': 2 * c,        # (ct_i, r_i)
            'participant_to_ledger_B': c,             # c_i
            'curator_to_ledger_B': c + rsum,          # ct_sum, r_sum
            'analyst_to_ledger_B': 8 + 4 * c + 2 * c}  # sum, ct0, ct'_sum, rho, pi0 = (a, z)


# ---------------------------------------------------------------------------
# --check
# ---------------------------------------------------------------------------

def check(bits):
    fails = 0

    def ok(cnd, msg):
        nonlocal fails
        print(("  PASS: " if cnd else "  FAIL: ") + msg)
        fails += (not cnd)

    t0 = time.perf_counter()
    K = Keys(bits)
    print(f"Masquerade, |N| = {K.N.bit_length()} bits (key generation {time.perf_counter() - t0:.1f} s):")
    order = K.N * K.lam
    ok(gmpy2.powmod(K.g_m, order, K.N2) == 1 and K.e > K.N2 and gmpy2.is_prime(K.e),
       "e is a prime > N^2 and g_m has order dividing N*lambda")
    n = 8
    xs = [secrets.randbelow(2 ** 16) for _ in range(n)]
    out = [participant(K, x) for x in xs]
    led = [o[0] for o in out]
    priv = [o[1] for o in out]
    ct_sum, r_sum = curator(K, led, priv)
    pub = analyst(K, led, ct_sum, r_sum)
    ok(pub['sum'] == sum(xs), f"analyst decrypts the exact sum {sum(xs)}")
    ok(auditor(K, led, ct_sum, r_sum, pub), "auditor accepts the honest run")

    bad = list(priv)
    bad[0] = (priv[0][0], priv[0][1] + 1)
    try:
        curator(K, led, bad)
        v = False
    except ValueError:
        v = True
    ok(v, "curator rejects a participant whose (ct_i, r_i) does not open c_i")

    for label, (cs, rs) in {
        "curator omits a participant": curator(K, led[1:], priv[1:]),
        "curator counts a participant twice": curator(K, led + led[:1], priv + priv[:1]),
        "curator alters ct_sum": ((ct_sum * (1 + 1000 * K.N)) % K.N2, r_sum),
    }.items():
        try:
            analyst(K, led, cs, rs)
            v = False
        except ValueError:
            v = True
        ok(v, f"{label}: the analyst's audit (Eq. 4) fails")
        ok(not auditor(K, led, cs, rs, pub), f"{label}: the public auditor rejects")

    wrong = dict(pub)
    rho = rand_unit(K.N2)
    wrong['sum'], wrong['rho'] = pub['sum'] + 1, rho
    wrong['ct_p'] = enc(K, pub['sum'] + 1, rho)
    wrong['ct0'] = (ct_sum * gmpy2.invert(wrong['ct_p'], K.N2)) % K.N2
    rho0 = gmpy2.powmod(wrong['ct0'] % K.N, K.d, K.N)
    wrong['pi0'] = prove_zero(K, wrong['ct0'], rho0)
    ok(not auditor(K, led, ct_sum, r_sum, wrong), "analyst publishing sum + 1 (with a best-effort proof) is rejected")
    tz = dict(pub)
    tz['pi0'] = (pub['pi0'][0], (pub['pi0'][1] * 2) % K.N2)
    ok(not auditor(K, led, ct_sum, r_sum, tz), "a tampered decryption proof is rejected")

    neg = K.N - 5                                     # "-5" in Z_N
    o = participant(K, neg)
    c2, r2 = curator(K, led + [o[0]], priv + [o[1]])
    p2 = analyst(K, led + [o[0]], c2, r2)
    print(f"  NOTE: a participant submitting an out-of-range input (-5 mod N) is accepted by the curator, the "
          f"analyst and the auditor ({auditor(K, led + [o[0]], c2, r2, p2)}); the published sum is {p2['sum']} "
          f"= {sum(xs)} - 5 -- base Masquerade has no input validation (zk-Masquerade adds it)")
    print("ALL PASSED" if not fails else f"{fails} FAILED")
    return fails


# ---------------------------------------------------------------------------
# --bench
# ---------------------------------------------------------------------------

N_SWEEP = [50, 100, 250, 500, 750, 1000]
N_TRIALS = {50: 10, 100: 10, 250: 10, 500: 5, 750: 3, 1000: 3}

STAGES = """Stage definitions (wall clock, time.perf_counter, single process, sequential)
  keygen_s             analyst Key-Generation, once per run (excluded from per-round figures)
  part_enc_ms          one participant: ct_i = Enc(m_i, rho_i)           (median over the n participants)
  part_commit_ms       one participant: c_i = Com(ct_i, r_i)              (median over the n participants)
  part_total_ms        one participant: enc + commit                      (median over the n participants)
  cur_verify_ms        curator: n commitment openings
  cur_aggregate_ms     curator: ct_sum and r_sum
  cur_total_ms         curator total
  ana_audit_ms         analyst: prod c_i == Com(ct_sum, r_sum)
  ana_decrypt_ms       analyst: Dec(ct_sum)
  ana_prove_ms         analyst: ct'_sum, ct_0, witness and Protocol 1 proof
  ana_total_ms         analyst total
  aud_commits_ms       auditor: prod c_i == Com(ct_sum, r_sum)     (O(n))
  aud_decryption_ms    auditor: ct'_sum, ct_0 and Protocol 1 verification
  aud_total_ms         auditor total
  *_B                  message sizes; elements of Z_{N^2} at |N^2|/8 bytes, sum 8 B"""


def stats(vals):
    s = sorted(vals)

    def qq(p):
        if len(s) == 1:
            return s[0]
        pos = (len(s) - 1) * p
        lo = math.floor(pos)
        hi = min(lo + 1, len(s) - 1)
        return s[lo] + (s[hi] - s[lo]) * (pos - lo)
    return {'mean': statistics.mean(s), 'std': statistics.stdev(s) if len(s) > 1 else 0.0,
            'median': qq(.5), 'q1': qq(.25), 'q3': qq(.75)}


def bench(a):
    out = a.out or 'masquerade_results'
    os.makedirs(out, exist_ok=True)
    Ns = a.n or N_SWEEP
    data = None
    
    print(f"Analyst key generation (|N| = {a.modulus_bits}, safe primes) ...")
    t0 = time.perf_counter()
    K = Keys(a.modulus_bits)
    keygen = time.perf_counter() - t0
    print(f"  done in {keygen:.1f} s")
    with open(os.path.join(out, 'masquerade_env.txt'), 'w') as f:
        f.write(f"scheme: Masquerade (base, not zk-Masquerade), Mouris & Tsoutsos, ACM TOIT 2025 -- re-implementation\n"
                f"Paillier + multiplicative commitment over N^2, |N| = {K.N.bit_length()}, |e| = {K.e.bit_length()} "
                f"(gmpy2 {gmpy2.version()} / GMP)\nkey generation: {keygen:.2f} s (once per run)\n"
                f"n = {Ns}, trials = {a.trials or N_TRIALS}, warm-up = 1 round (n = 8)\n"
                f"readings: {a.data or 'uniform random in [0, 2^16)'}\n"
                f"python {sys.version.split()[0]}, {platform.platform()}, {platform.machine()}\n\n{STAGES}\n")

    o = [participant(K, 1) for _ in range(8)]
    cs, rs = curator(K, [x[0] for x in o], [x[1] for x in o])
    pb = analyst(K, [x[0] for x in o], cs, rs)
    auditor(K, [x[0] for x in o], cs, rs, pb)

    rows = []
    for n in Ns:
        trials = a.trials or N_TRIALS.get(n, 3)
        for tr in range(trials):
            xs = ([data[i % len(data)] for i in range(n)] if data is not None
                  else [secrets.randbelow(2 ** 16) for _ in range(n)])
            enc_t, com_t, led, priv = [], [], [], []
            for x in xs:
                tm = {}
                c, p_ = participant(K, x, tm)
                led.append(c)
                priv.append(p_)
                enc_t.append(tm['enc'])
                com_t.append(tm['commit'])
            tc, ta, tu = {}, {}, {}
            ct_sum, r_sum = curator(K, led, priv, tc)
            pub = analyst(K, led, ct_sum, r_sum, ta)
            okv = auditor(K, led, ct_sum, r_sum, pub, tu)
            if not okv or pub['sum'] != sum(xs):
                raise AssertionError(f"round failed at n={n}: auditor={okv}, sum={pub['sum']} vs {sum(xs)}")
            ms = lambda v: v * 1000.0
            med = lambda v: stats(v)['median']
            r = {'n': n, 'trial': tr, 'modulus_bits': K.N.bit_length(),
                 'part_enc_ms': ms(med(enc_t)), 'part_commit_ms': ms(med(com_t)),
                 'part_total_ms': ms(med([x + y for x, y in zip(enc_t, com_t)])),
                 'all_part_serial_ms': ms(sum(enc_t) + sum(com_t)),
                 'cur_verify_ms': ms(tc['cur_verify']), 'cur_aggregate_ms': ms(tc['cur_aggregate']),
                 'cur_total_ms': ms(tc['cur_verify'] + tc['cur_aggregate']),
                 'ana_audit_ms': ms(ta['ana_audit']), 'ana_decrypt_ms': ms(ta['ana_decrypt']),
                 'ana_prove_ms': ms(ta['ana_prove']), 'ana_total_ms': ms(sum(ta.values())),
                 'aud_commits_ms': ms(tu['aud_commits']), 'aud_decryption_ms': ms(tu['aud_decryption']),
                 'aud_total_ms': ms(sum(tu.values()))}
            r.update(sizes(K, n))
            rows.append(r)
            print(f"n={n:5d} trial {tr + 1}/{trials}: participant {r['part_total_ms']:.1f} ms | curator "
                  f"{r['cur_total_ms'] / 1000:.2f} s | analyst {r['ana_total_ms']:.1f} ms | auditor "
                  f"{r['aud_total_ms']:.1f} ms")
        with open(os.path.join(out, 'masquerade_trials.csv'), 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

    summ = []
    for n in Ns:
        rs_ = [r for r in rows if r['n'] == n]
        sr = {'n': n, 'trials': len(rs_), 'modulus_bits': K.N.bit_length()}
        for k in rs_[0]:
            if k in sr or k == 'trial':
                continue
            for st, v in stats([float(r[k]) for r in rs_]).items():
                sr[f'{k}_{st}'] = v
        summ.append(sr)
    with open(os.path.join(out, 'masquerade_summary.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(summ[0].keys()))
        w.writeheader()
        w.writerows(summ)
    print(f"Wrote masquerade_trials.csv, masquerade_summary.csv, masquerade_env.txt in {out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--bench', action='store_true')
    ap.add_argument('--modulus-bits', type=int, default=2048, help='|N| (default 2048, the paper\'s setting)')
    ap.add_argument('--n', type=int, nargs='+', default=None)
    ap.add_argument('--trials', type=int, default=None)
    ap.add_argument('--data', default=None)
    ap.add_argument('--column', type=int, default=0)
    ap.add_argument('--no-header', action='store_true')
    ap.add_argument('--decimals', type=int, default=3)
    ap.add_argument('--out', default=None)
    a = ap.parse_args()
    if a.check:
        return 1 if check(a.modulus_bits) else 0
    if a.bench:
        bench(a)
        return 0
    ap.print_help()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())