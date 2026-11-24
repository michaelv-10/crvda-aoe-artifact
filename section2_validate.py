"""
section2_validate.py -- validate the actual implementation
======================================================================================

Part 1 (--part wire): ONE COMPLETE ROUND OVER THE WIRE. Every party is a
separate object built only from what it would really hold -- the encoded public
parameters plus its own encoded secret -- and every message is passed as bytes
and decoded by its receiver:

  dealer --PP, keys--> parties
  meter i --R_i--> AG --(t,d,C,T)--> each quorum member --theta_j--> AG
  AG --Gamma_t--> DC --Omega_t--> public verifier

All algorithms run: Setup, Report, VerifyRep (inside GoodTrans), Build,
GoodTrans, CertShare, CertCombine, AggrDec, DecProve, Verify. The range proof
in every report is generated and checked. Checks: exact message lengths,
decode(encode(m)) round trips byte-for-byte, Verify accepts and X_t equals the
true sum, a repeated Report on the same label returns the cached report
(identical bytes), and a list of tampered messages is rejected -- each at the
step that should catch it (decoder, VerifyRep, GoodTrans, CertCombine,
AggrDec or Verify).

Part 2 (--part sweep): for each n (k = ceil(20% of n)) one round is generated
and, from the actual encoded bytes, the script records
  * s2_sizes.csv   exact byte length of R_i, the transcript, the AG->Q_j
                   message, theta_j, Gamma_t, Omega_t, the public parameters /
                   roster and each party's secret key material;
  * s2_storage.csv persistent storage per party (what each party keeps
                   between rounds), including the DC's discrete-log table;
  * s2_memory.csv  PEAK RUNTIME MEMORY, measured separately for each role in a
                   FRESH PROCESS that holds only that role's inputs (decoded
                   from bytes): meter (Report), certifier (GoodTrans +
                   CertShare), AG (Build + CertCombine), DC (discrete-log
                   table + AggrDec + DecProve) and verifier (Verify).

Memory method: each role runs in a fresh process
that holds only that role's inputs. Resident set size (RSS) is read with
psutil; the peak of a phase is found by sampling RSS every 2 ms from a
background thread while the phase runs (process-wide peak counters are not
used: on Linux they also count the memory of the launching process).
For each role the script reports
  rss_start      after imports and building the party from its public/secret data
  rss_input      after decoding the role's input messages
  peak           maximum RSS sampled during the role's computation
  input_MiB      = rss_input - rss_start   (memory to hold the decoded inputs)
  working_MiB    = peak - rss_input        (extra memory used by the computation)
For the DC, table_MiB is the RSS growth while building the bounded
discrete-log table. RSS includes the Python interpreter and Charm (reported
as rss_start), so compare the *_MiB increments across n, not raw peaks.

The values of the readings do not affect sizes or memory, so uniform random
readings are used here.

Usage
  python3 section2_validate.py                 # Part 1, then the full sweep
  python3 section2_validate.py --part wire     # Part 1 only (seconds)
  python3 section2_validate.py --part sweep    # sizes, storage, memory
  python3 section2_validate.py --n 50 100      # sweep only these n
  python3 section2_validate.py --smoke         # quick check of everything (n = 10, 20)
  caffeinate -i python3 section2_validate.py | tee s2.log     # macOS

Outputs (in --out, default s2_results; s2_smoke with --smoke):
  s2_wire_check.txt, s2_sizes.csv, s2_storage.csv, s2_memory.csv, s2_env.txt
"""

import argparse
import csv
import gc
import json
import math
import os
import platform
import random as pyrandom
import subprocess
import sys
import tempfile
import time

from charm.toolbox.pairinggroup import PairingGroup, G1, G2

import crvda_aoe_v2 as C
from crvda_wire import Wire, WireError, ZR_BYTES, ID_BYTES

N_SWEEP = [50, 100, 250, 500, 750, 1000]
K_PCT = 20
MiB = 2 ** 20


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def k_of(n, pct):
    return min(math.ceil(pct / 100 * n), n - 2)


try:
    import psutil
    _PROC = psutil.Process()

    def rss_now():
        """Current resident set size of this process, in bytes."""
        return _PROC.memory_info().rss

    SAMPLE_S, MEM_METHOD = 0.002, 'psutil RSS sampled every 2 ms during the phase'
except ImportError:                                   # fallback: slower, coarser
    def rss_now():
        out = subprocess.run(['ps', '-o', 'rss=', '-p', str(os.getpid())],
                             capture_output=True, text=True).stdout.strip()
        return int(out) * 1024                        # ps reports KiB on macOS and Linux

    SAMPLE_S, MEM_METHOD = 0.05, 'ps RSS sampled every 50 ms (install psutil for 2 ms sampling)'


class PeakRSS:
    """Peak resident set size DURING a phase, found by sampling the current
    RSS from a background thread (plus one sample at the end, while the
    phase's objects are still alive). The process-wide peak counter
    (getrusage ru_maxrss) is not used: on Linux it also counts the memory of
    the process that launched this one, so it cannot isolate a phase."""

    def __enter__(self):
        import threading
        self.peak, self._stop = rss_now(), False

        def loop():
            while not self._stop:
                self.peak = max(self.peak, rss_now())
                time.sleep(SAMPLE_S)

        self._t = threading.Thread(target=loop, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *exc):
        self.peak = max(self.peak, rss_now())
        self._stop = True
        self._t.join()
        return False


def settle():
    gc.collect()
    return rss_now()


class Log:
    def __init__(self, path=None):
        self.lines, self.path, self.fails = [], path, 0

    def __call__(self, msg=''):
        print(msg)
        self.lines.append(msg)

    def check(self, cond, msg):
        self(("  PASS: " if cond else "  FAIL: ") + msg)
        if not cond:
            self.fails += 1

    def save(self):
        if self.path:
            with open(self.path, 'w') as f:
                f.write("\n".join(self.lines) + "\n")


# ---------------------------------------------------------------------------
# Part 1: a complete round over the wire, plus rejection tests
# ---------------------------------------------------------------------------

def wire_round(log, n=10, k=2, L=16, seed=11):
    rng = pyrandom.Random(seed)
    dealer = C.CRVDA_AOE('BN254')
    dealer.setup(n, k, L, sid=b'section2-wire')
    W = Wire(dealer.group)
    g1s = W.size[G1]
    log(f"Point encoding: {'compact (G1 32 B, G2 64 B)' if W.compact else 'Charm raw (fallback)'}; "
        f"layout G1={W.layout[G1]}, G2={W.layout[G2]}")
    log(f"Round: n = {n}, k = {k}, L = {L}")

    # ---- dealer -> parties ----
    pub = W.enc_public(dealer)
    meters = {i: W.add_secret(W.dec_public(pub), W.enc_meter_secret(dealer, i)) for i in range(1, n + 1)}
    certs = {j: W.add_secret(W.dec_public(pub), W.enc_cert_secret(dealer, j)) for j in dealer.Q}
    ag = W.dec_public(pub)
    dc = W.add_secret(W.dec_public(pub), W.enc_dc_secret(dealer))
    ver = W.dec_public(pub)
    log.check(W.enc_public(ag) == pub, "public parameters: decode -> encode reproduces the bytes")
    log.check(ag.hx == dealer.hx and ag.g_vec == dealer.g_vec and ag.h_vec == dealer.h_vec,
              "range-proof generators re-derived by hashing match the dealer's")

    # ---- meters -> AG ----
    t = 7
    xs = [rng.randint(0, 2 ** L - 1) for _ in range(n)]
    rep_bytes = {}
    for i in range(1, n + 1):
        R = meters[i].report(i, t, xs[i - 1])
        rep_bytes[i] = W.enc_report(meters[i], R, t)
    rl = W.report_len(L)
    log.check(all(len(b) == rl for b in rep_bytes.values()), f"every R_i is exactly {rl} bytes")
    again = W.enc_report(meters[1], meters[1].report(1, t, xs[0]), t)
    log.check(again == rep_bytes[1], "repeated Report on the same label returns the cached report (identical bytes)")

    decoded = [W.dec_report(ag, rep_bytes[i])[0] for i in range(1, n + 1)]
    log.check(all(W.enc_report(ag, R, t) == rep_bytes[R[0]] for R in decoded),
              "R_i: decode -> encode reproduces the bytes")
    log.check(all(ag.verify_rep(R) for R in decoded),
              "every decoded R_i passes VerifyRep (signature, linking proof, range proof)")

    # ---- AG Build -> quorum ----
    T, Ct, d = ag.build(t, decoded)
    dist = W.enc_dist(ag, t, T, Ct, d)
    log.check(len(dist) == W.dist_len(n, L), f"AG->Q_j transcript message is {len(dist)} bytes = 68 + n x {rl}")

    shares_b = {}
    for j, cp in certs.items():
        t2, T2, C2, d2 = W.dec_dist(cp, dist)
        shares_b[j] = W.enc_share(cp.cert_share(j, t2, T2, C2, d2))
    log.check(all(len(b) == g1s for b in shares_b.values()), f"every theta_j is {g1s} bytes")

    # ---- AG CertCombine -> DC ----
    shares = {j: W.dec_share(b) for j, b in shares_b.items()}
    Gamma = ag.cert_combine_gamma(t, Ct, d, shares)
    gb = W.enc_gamma(ag, t, Gamma)
    log.check(len(gb) == W.gamma_len(), f"Gamma_t is {len(gb)} bytes")

    # ---- DC -> verifier ----
    Gd, _ = W.dec_gamma(dc, gb)
    log.check(W.enc_gamma(dc, t, Gd) == gb, "Gamma_t: decode -> encode reproduces the bytes")
    Xt, Zt = dc.aggr_dec_gamma(Gd)
    pi = dc.dec_prove(Gd, Xt, Zt)
    ob = W.enc_omega(dc, t, (Gd, Xt, Zt, pi))
    log.check(len(ob) == W.omega_len(ver), f"Omega_t is {len(ob)} bytes (X_t field of {len(ob) - 292} bytes)")

    Om, _ = W.dec_omega(ver, ob)
    log.check(W.enc_omega(ver, t, Om) == ob, "Omega_t: decode -> encode reproduces the bytes")
    log.check(ver.verify_omega(Om), "public Verify(Omega_t) accepts")
    log.check(Om[1] == sum(xs), f"recovered X_t = {Om[1]} equals the true sum {sum(xs)}")

    # ======================= rejection tests ==================================
    log("Rejection tests (each tampered message must be rejected):")
    p = W.p

    def report_verdict(b):
        try:
            R, _ = W.dec_report(ag, b)
        except WireError:
            return 'decoder'
        return 'VerifyRep' if not ag.verify_rep(R) else 'ACCEPTED'

    def expect(where_ok, verdict, msg):
        log.check(verdict in where_ok, f"{msg}: rejected by {verdict}")

    good = rep_bytes[2]
    R2, _ = W.dec_report(ag, good)
    i2, ell2, C2_, (V2, pl2, pr2), (sR2, sz2) = R2
    one = dealer.group.init(C.ZR, 1)

    expect({'VerifyRep'}, report_verdict(W.enc_report(ag, (i2, ell2, C2_ * ag.g1, (V2, pl2, pr2), (sR2, sz2)), t)),
           "R_i with a different ciphertext")
    bad_pl = tuple(pl2[:3]) + (pl2[3] + one,) + tuple(pl2[4:])
    expect({'VerifyRep'}, report_verdict(W.enc_report(ag, (i2, ell2, C2_, (V2, bad_pl, pr2), (sR2, sz2)), t)),
           "R_i with a changed linking-proof scalar")
    bad_pr = dict(pr2)
    bad_pr['t'] = pr2['t'] + one
    expect({'VerifyRep'}, report_verdict(W.enc_report(ag, (i2, ell2, C2_, (V2, pl2, bad_pr), (sR2, sz2)), t)),
           "R_i with a changed range-proof scalar")
    expect({'VerifyRep'}, report_verdict(W.enc_report(ag, (i2, ell2, C2_, (V2, pl2, pr2), (sR2, sz2 + one)), t)),
           "R_i with a changed signature")

    b = bytearray(good); b[0:2] = (3).to_bytes(2, 'big')
    expect({'VerifyRep'}, report_verdict(bytes(b)), "R_i claiming another meter's identity")
    b = bytearray(good); b[0:2] = (n + 1).to_bytes(2, 'big')
    expect({'VerifyRep'}, report_verdict(bytes(b)), "R_i with an unregistered identity")
    b = bytearray(good); b[2:6] = (t + 1).to_bytes(4, 'big')
    expect({'VerifyRep'}, report_verdict(bytes(b)), "R_i replayed under another round number")
    expect({'decoder'}, report_verdict(good[:-1]), "R_i truncated by one byte")
    expect({'decoder'}, report_verdict(good + b'\x00'), "R_i with one extra byte")
    zx_off = ID_BYTES + 4 + 5 * g1s
    b = bytearray(good); b[zx_off:zx_off + ZR_BYTES] = (p + 3).to_bytes(ZR_BYTES, 'big')
    expect({'decoder'}, report_verdict(bytes(b)), "R_i with a non-canonical scalar (>= group order)")
    if W.compact:
        b = bytearray(good); b[6] ^= 0x80
        expect({'decoder', 'VerifyRep'}, report_verdict(bytes(b)), "R_i with the ciphertext's sign bit flipped")

    # transcript
    def trans_verdict(Tlist, Cx=Ct, dx=d, raw=None):
        try:
            data = raw if raw is not None else W.enc_dist(ag, t, Tlist, Cx, dx)
            cp = certs[dealer.Q[0]]
            tt, TT, CC, dd = W.dec_dist(cp, data)
        except WireError:
            return 'decoder'
        return 'GoodTrans' if not cp.good_trans(tt, TT, CC, dd) else 'ACCEPTED'

    expect({'decoder'}, trans_verdict(None, raw=dist[:-rl]), "transcript with one report missing")
    sw = list(T); sw[0], sw[1] = sw[1], sw[0]
    expect({'GoodTrans'}, trans_verdict(sw), "transcript with two reports out of order")
    dup = list(T); dup[1] = dup[0]
    expect({'GoodTrans'}, trans_verdict(dup), "transcript with a repeated identity (one meter's report twice)")
    expect({'GoodTrans'}, trans_verdict(T, dx=bytes([d[0] ^ 1]) + d[1:]), "transcript with an altered digest d")
    expect({'GoodTrans'}, trans_verdict(T, Cx=Ct * ag.g1), "transcript with an altered aggregate C_t")

    # shares
    bad_sh = dict(shares)
    bad_sh[dealer.Q[0]] = shares[dealer.Q[0]] * ag.g1
    try:
        ag.cert_combine_gamma(t, Ct, d, bad_sh)
        v = 'ACCEPTED'
    except ValueError:
        v = 'CertCombine'
    expect({'CertCombine'}, v, "incorrect BLS share theta_j")

    # Gamma
    def gamma_verdict(G):
        try:
            Gx, _ = W.dec_gamma(dc, W.enc_gamma(dc, t, G))
            dc.aggr_dec_gamma(Gx)
        except WireError:
            return 'decoder'
        except ValueError:
            return 'AggrDec'
        return 'ACCEPTED'

    ell_g, d_g, C_g, tau_g = Gd
    expect({'AggrDec'}, gamma_verdict((ell_g, d_g, C_g, tau_g * ag.g1)), "Gamma_t with an altered certificate tau")
    expect({'AggrDec'}, gamma_verdict((ell_g, bytes([d_g[0] ^ 1]) + d_g[1:], C_g, tau_g)), "Gamma_t with an altered digest d")
    expect({'AggrDec'}, gamma_verdict((ell_g, d_g, C_g * ag.g1, tau_g)), "Gamma_t with an altered aggregate C_t")

    # Omega
    def omega_verdict(O):
        try:
            Ox, _ = W.dec_omega(ver, W.enc_omega(ver, t, O))
        except WireError:
            return 'decoder'
        return 'Verify' if not ver.verify_omega(Ox) else 'ACCEPTED'

    G_o, X_o, Z_o, (D1, D2, D3, ys, yt) = Om
    expect({'Verify'}, omega_verdict((G_o, X_o + 1, Z_o, (D1, D2, D3, ys, yt))), "Omega_t claiming X_t + 1")
    expect({'Verify'}, omega_verdict((G_o, X_o, Z_o * ag.g1, (D1, D2, D3, ys, yt))), "Omega_t with an altered Z_t")
    expect({'Verify'}, omega_verdict((G_o, X_o, Z_o, (D1, D2, D3, ys + one, yt))), "incorrect recovery proof")
    expect({'Verify'}, omega_verdict(((ell_g, d_g, C_g, tau_g * ag.g1), X_o, Z_o, (D1, D2, D3, ys, yt))),
           "Omega_t with an altered certificate")

    # public parameters
    def pub_verdict(data):
        try:
            W.dec_public(data)
        except WireError:
            return 'decoder'
        return 'ACCEPTED'

    sidlen = pub[5]
    rid_off = 6 + sidlen
    b = bytearray(pub); b[rid_off] ^= 1
    expect({'decoder'}, pub_verdict(bytes(b)), "public parameters with an altered roster digest rid")
    wq_mod = W.dec_public(pub)
    wq_mod.WQ = wq_mod.WQ * wq_mod.g2
    expect({'decoder'}, pub_verdict(W.enc_public(wq_mod)), "public parameters whose W_Q is not the product of the W_j")

    return W


# ---------------------------------------------------------------------------
# Part 2: child roles (each runs in a fresh process)
# ---------------------------------------------------------------------------

def _read(d, name):
    with open(os.path.join(d, name), 'rb') as f:
        return f.read()


def child(role, d):
    meta = json.loads(_read(d, 'round.json'))
    group = PairingGroup('BN254')
    W = Wire(group)
    pub = _read(d, 'public.bin')
    out = {'role': role}

    if role == 'meter':
        P = W.add_secret(W.dec_public(pub), _read(d, 'meter.sec'))
        r0 = settle()
        r1 = r0                                         # a meter receives no input message
        t0 = time.perf_counter()
        with PeakRSS() as pk:
            R = P.report(1, meta['t'], meta['x1'])
            b = W.enc_report(P, R, meta['t'])
        out['phase_s'] = time.perf_counter() - t0
        peak = pk.peak
        assert len(b) == W.report_len(P.L)

    elif role == 'certifier':
        j = meta['j']
        P = W.add_secret(W.dec_public(pub), _read(d, 'cert.sec'))
        r0 = settle()
        t, T, Ct, dd = W.dec_dist(P, _read(d, 'dist.bin'))
        r1 = settle()
        t0 = time.perf_counter()
        with PeakRSS() as pk:
            theta = P.cert_share(j, t, T, Ct, dd)        # GoodTrans + BLS share
        out['phase_s'] = time.perf_counter() - t0
        peak = pk.peak
        assert W.enc_share(theta) == _read(d, 'share_j.bin'), "certifier share differs from expected"

    elif role == 'ag':
        P = W.dec_public(pub)
        r0 = settle()
        blob, rl = _read(d, 'reports.bin'), W.report_len(meta['L'])
        reports = [W.dec_report(P, blob[o:o + rl])[0] for o in range(0, len(blob), rl)]
        sblob, s = _read(d, 'shares.bin'), W.size[G1]
        shares = {j: W.dec_share(sblob[q * s:(q + 1) * s]) for q, j in enumerate(P.Q)}
        del blob, sblob
        r1 = settle()
        t0 = time.perf_counter()
        with PeakRSS() as pk:
            T, Ct, dd = P.build(meta['t'], reports)
            Gamma = P.cert_combine_gamma(meta['t'], Ct, dd, shares)
        out['phase_s'] = time.perf_counter() - t0
        peak = pk.peak
        assert W.enc_gamma(P, meta['t'], Gamma) == _read(d, 'gamma.bin'), "AG produced a different Gamma"

    elif role == 'dc':
        P = W.add_secret(W.dec_public(pub), _read(d, 'dc.sec'))
        r0 = settle()
        Gamma, _ = W.dec_gamma(P, _read(d, 'gamma.bin'))
        r1 = settle()
        t0 = time.perf_counter()
        with PeakRSS() as pt:
            P.build_bsgs()
        out['table_build_s'] = time.perf_counter() - t0
        r_tab = settle()
        out['table_entries'] = P._bsgs.m
        out['table_key_bytes'] = sum(len(k) for k in P._bsgs.table)
        out['table_MiB'] = (r_tab - r1) / MiB
        t0 = time.perf_counter()
        with PeakRSS() as pk:
            Xt, Zt = P.aggr_dec_gamma(Gamma)
            P.dec_prove(Gamma, Xt, Zt)
        out['phase_s'] = time.perf_counter() - t0
        peak = max(pt.peak, pk.peak)                    # the table is part of the DC's working memory
        assert Xt == meta['sum'], "DC recovered a wrong aggregate"

    elif role == 'verifier':
        P = W.dec_public(pub)
        r0 = settle()
        Om, _ = W.dec_omega(P, _read(d, 'omega.bin'))
        r1 = settle()
        t0 = time.perf_counter()
        with PeakRSS() as pk:
            ok = P.verify_omega(Om)
        out['phase_s'] = time.perf_counter() - t0
        peak = pk.peak
        assert ok and Om[1] == meta['sum'], "Verify failed"
    else:
        raise SystemExit(f"unknown role {role}")

    out.update({'rss_start_MiB': r0 / MiB, 'rss_input_MiB': r1 / MiB, 'peak_MiB': peak / MiB,
                'input_MiB': (r1 - r0) / MiB, 'working_MiB': max(peak - r1, 0) / MiB,
                'method': MEM_METHOD})
    print("RESULT " + json.dumps(out))


def run_child(role, d):
    proc = subprocess.run([sys.executable, os.path.abspath(__file__), '--child', role, '--dir', d],
                          capture_output=True, text=True)
    for line in proc.stdout.splitlines():
        if line.startswith('RESULT '):
            return json.loads(line[7:])
    raise RuntimeError(f"child '{role}' failed:\n{proc.stdout}\n{proc.stderr}")


# ---------------------------------------------------------------------------
# Part 2: sweep driver
# ---------------------------------------------------------------------------

def sweep_point(n, k, L, seed, work):
    rng = pyrandom.Random(seed + n)
    sch = C.CRVDA_AOE('BN254')
    sch.setup(n, k, L, sid=f"s2-{n}-{k}".encode())
    W = Wire(sch.group)
    t = 1
    xs = [rng.randint(0, 2 ** L - 1) for _ in range(n)]

    t0 = time.perf_counter()
    reports = [sch.report(i, t, xs[i - 1]) for i in range(1, n + 1)]
    T, Ct, d = sch.build(t, reports)
    Hcm = sch._cert_message_hash(t, Ct, d)
    shares = {j: Hcm ** sch.z[j] for j in sch.Q}          # = CertShare output (GoodTrans run in the child)
    tau = shares[sch.Q[0]]
    for j in sch.Q[1:]:
        tau = tau * shares[j]
    Gamma = sch.make_gamma(t, Ct, d, tau)
    sch.build_bsgs()
    Xt, Zt = sch.aggr_dec_gamma(Gamma)
    Omega = (Gamma, Xt, Zt, sch.dec_prove(Gamma, Xt, Zt))
    assert Xt == sum(xs) and sch.verify_omega(Omega)
    gen_s = time.perf_counter() - t0

    enc = {
        'public.bin': W.enc_public(sch),
        'meter.sec': W.enc_meter_secret(sch, 1),
        'cert.sec': W.enc_cert_secret(sch, sch.Q[0]),
        'dc.sec': W.enc_dc_secret(sch),
        'reports.bin': b''.join(W.enc_report(sch, R, t) for R in reports),
        'dist.bin': W.enc_dist(sch, t, T, Ct, d),
        'share_j.bin': W.enc_share(shares[sch.Q[0]]),
        'shares.bin': b''.join(W.enc_share(shares[j]) for j in sch.Q),
        'gamma.bin': W.enc_gamma(sch, t, Gamma),
        'omega.bin': W.enc_omega(sch, t, Omega),
        'round.json': json.dumps({'t': t, 'x1': xs[0], 'sum': sum(xs), 'L': L,
                                  'j': sch.Q[0]}).encode(),
    }
    d_dir = os.path.join(work, f"n{n}")
    os.makedirs(d_dir, exist_ok=True)
    for name, data in enc.items():
        with open(os.path.join(d_dir, name), 'wb') as f:
            f.write(data)

    g1s, g2s = W.size[G1], W.size[G2]
    rl = W.report_len(L)
    sizes = {
        'n': n, 'k': k, 'L': L, 'point_encoding': 'compact' if W.compact else 'charm-raw',
        'report_B': rl,
        'transcript_B': n * rl,
        'dist_msg_B': len(enc['dist.bin']),
        'share_B': len(enc['share_j.bin']),
        'gamma_B': len(enc['gamma.bin']),
        'omega_B': len(enc['omega.bin']),
        'public_params_B': len(enc['public.bin']),
        'meter_secret_B': len(enc['meter.sec']),
        'cert_secret_B': len(enc['cert.sec']),
        'dc_secret_B': len(enc['dc.sec']),
    }
    sizes['total_sent_B'] = (n * rl + (k + 1) * sizes['dist_msg_B'] + (k + 1) * sizes['share_B']
                             + sizes['gamma_B'] + sizes['omega_B'])
    assert len(enc['reports.bin']) == n * rl

    hdr = 2 + 2 + 1 + 1 + len(sch.sid) + 32                     # n, k, L, |sid|, sid, rid
    storage = [
        ('meter', 'secret keys (s_i, t_i, rho_i, rsk_i)', sizes['meter_secret_B'], 'persistent'),
        ('meter', 'public data used by Report (header, g1, u, h, K_i)', hdr + 4 * g1s, 'persistent'),
        ('meter', 'range-proof generators hx, g_vec, h_vec (optional cache)', (2 * L + 1) * g1s,
         'persistent, re-derivable by hashing'),
        ('meter', 'cached report for the open round (encrypt-once)', rl, 'per round, until the round closes'),
        ('certifier (meter in Q), in addition', 'certification key z_j', sizes['cert_secret_B'], 'persistent'),
        ('certifier (meter in Q), in addition', 'roster (i, rvk_i, K_i) for all n meters', n * (ID_BYTES + 2 * g1s),
         'persistent'),
        ('AG', 'public data for CertCombine (header, g2, (j, W_j) for Q)', hdr + g2s + (k + 1) * (ID_BYTES + g2s),
         'persistent'),
        ('AG', 'transcript T_t and Gamma_t kept for audit (optional)', n * rl + sizes['gamma_B'],
         'per round, if archived'),
        ('DC', 'decryption key (s0, t0)', sizes['dc_secret_B'], 'persistent'),
        ('DC', 'public data (header, g1, g2, W_Q)', hdr + g1s + 2 * g2s, 'persistent'),
        ('verifier', 'public data (header, g1, S0, T0, g2, W_Q)', hdr + 3 * g1s + 2 * g2s, 'persistent'),
        ('all parties', 'full public parameters and roster (as distributed)', sizes['public_params_B'],
         'distributed once at setup'),
    ]
    return sizes, storage, d_dir, gen_s


def run_sweep(Ns, k_pct, L, seed, out_dir, log):
    work = tempfile.mkdtemp(prefix='s2work-')
    size_rows, storage_rows, mem_rows = [], [], []
    for n in Ns:
        k = k_of(n, k_pct)
        t0 = time.perf_counter()
        sizes, storage, d_dir, gen_s = sweep_point(n, k, L, seed, work)
        size_rows.append(sizes)
        for party, comp, nbytes, note in storage:
            storage_rows.append({'n': n, 'k': k, 'party': party, 'component': comp, 'bytes': nbytes,
                                 'when': note})
        for role in ('meter', 'certifier', 'ag', 'dc', 'verifier'):
            r = run_child(role, d_dir)
            row = {'n': n, 'k': k, 'role': role}
            for key in ('rss_start_MiB', 'rss_input_MiB', 'peak_MiB', 'input_MiB', 'working_MiB', 'phase_s',
                        'table_entries', 'table_key_bytes', 'table_MiB', 'table_build_s'):
                row[key] = r.get(key, '')
            mem_rows.append(row)
            if role == 'dc':
                storage_rows.append({'n': n, 'k': k, 'party': 'DC',
                                     'component': f"discrete-log table, {r['table_entries']} entries "
                                                  f"(as implemented: Charm-serialized keys)",
                                     'bytes': r['table_key_bytes'] + 4 * r['table_entries'],
                                     'when': 'persistent (depends only on n, L), or rebuilt at start-up'})
                storage_rows.append({'n': n, 'k': k, 'party': 'DC',
                                     'component': 'discrete-log table, compact form (32 B point + 4 B index)',
                                     'bytes': r['table_entries'] * (W_SIZE_G1 + 4),
                                     'when': 'persistent'})
        cert = [m for m in mem_rows if m['n'] == n and m['role'] == 'certifier'][0]
        dcr = [m for m in mem_rows if m['n'] == n and m['role'] == 'dc'][0]
        log(f"n={n:5d} k={k:4d}: |R|={sizes['report_B']} B, |Gamma|={sizes['gamma_B']} B, "
            f"|Omega|={sizes['omega_B']} B, PP={sizes['public_params_B']} B | certifier: transcript "
            f"{cert['input_MiB']:.1f} MiB + GoodTrans {cert['working_MiB']:.1f} MiB | DC table "
            f"{dcr['table_entries']} entries ({dcr['table_MiB']:.1f} MiB) "
            f"[{time.perf_counter() - t0:.0f} s]")

    for name, rows in (('s2_sizes.csv', size_rows), ('s2_storage.csv', storage_rows),
                       ('s2_memory.csv', mem_rows)):
        with open(os.path.join(out_dir, name), 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)


W_SIZE_G1 = 32


def main(argv=None):
    global W_SIZE_G1
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument('--part', choices=('wire', 'sweep', 'all'), default='all')
    ap.add_argument('--n', type=int, nargs='+', default=None)
    ap.add_argument('--k-pct', type=int, default=K_PCT)
    ap.add_argument('--L', type=int, default=16)
    ap.add_argument('--seed', type=int, default=1234)
    ap.add_argument('--smoke', action='store_true', help='quick check: n = 10, 20')
    ap.add_argument('--out', default=None)
    ap.add_argument('--child', default=None, help=argparse.SUPPRESS)
    ap.add_argument('--dir', default=None, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    if args.child:
        child(args.child, args.dir)
        return 0

    out_dir = args.out or ('s2_smoke' if args.smoke else 's2_results')
    os.makedirs(out_dir, exist_ok=True)
    Ns = [10, 20] if args.smoke else (args.n or N_SWEEP)

    with open(os.path.join(out_dir, 's2_env.txt'), 'w') as f:
        f.write(f"python: {sys.version.split()[0]}\nplatform: {platform.platform()}\n"
                f"machine: {platform.machine()}\ncharm: {C._charm_version()}\ncurve: BN254\nL: {args.L}\n"
                f"n: {Ns}\nk: ceil({args.k_pct}% of n)\nmemory: {MEM_METHOD}; each role in a fresh "
                f"process holding only its own inputs\n")

    log = Log(os.path.join(out_dir, 's2_wire_check.txt'))
    if args.part in ('wire', 'all'):
        log("== Part 1: complete round over the wire ==")
        W = wire_round(log, L=args.L)
        W_SIZE_G1 = W.size[G1]
        log(f"Part 1: {'ALL PASSED' if log.fails == 0 else f'{log.fails} FAILED'}")
        log.save()
        if log.fails:
            return 1
    else:
        W_SIZE_G1 = Wire(PairingGroup('BN254')).size[G1]

    if args.part in ('sweep', 'all'):
        log("\n== Part 2: sizes, storage and peak memory per n ==")
        run_sweep(Ns, args.k_pct, args.L, args.seed, out_dir, log)
        log(f"Wrote s2_sizes.csv, s2_storage.csv, s2_memory.csv, s2_env.txt in {out_dir}")
    log.save()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())