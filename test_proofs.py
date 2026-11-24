"""
test_proofs.py -- targeted checks that the linking proof and the Bulletproof
range proof in crvda_aoe.py actually constrain the reported data.

Run (same folder as crvda_aoe.py):   python3 test_proofs.py

Part 1 works on the CURRENT crvda_aoe.py. A corrupted meter builds a range
proof for a commitment to an OUT-OF-RANGE value by deriving every Fiat-Shamir
challenge first and solving for V afterwards (possible because V is not hashed
into the range-proof transcript). On the current code the report passes
VerifyRep and GoodTrans, gets certified, and then AggrDec fails. After the
patch (V bound into the transcript) Part 1 must report PASS.

Part 2 needs the patched signature range_prove_bp(..., V, x_int, gamma, L, ctx).
It checks that honest proofs accept and that mismatched, wrong-key,
out-of-range and tampered proofs reject -- each at the step that is supposed to
catch it (re-signing tampered reports with the meter's own key, so the report
signature cannot mask a missing proof check).
"""

import inspect
import random as pyrandom

from charm.toolbox.pairinggroup import ZR

from crvda_aoe_v2 import (CRVDA_AOE, cat, fs_challenge, hash_to_g1, inner_product,
                       ipa_prove, link_prove, link_verify, range_prove_bp,
                       range_verify_bp, schnorr_sign, vec_commit, zneg, zr_powers)

N, K, L = 5, 1, 16
PATCHED = 'V' in inspect.signature(range_prove_bp).parameters


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def fresh(sid):
    sch = CRVDA_AOE('BN254')
    sch.setup(N, K, L, sid=sid)
    sch.build_bsgs()
    return sch


def contexts(sch, i, t):
    ell_t = sch.ell(t)
    A = hash_to_g1(sch.group, b'H1', ell_t)
    B = hash_to_g1(sch.group, b'H2', ell_t)
    link_ctx = [sch.sid, ell_t, i]
    range_ctx = [b'RANGE-CTX', sch.sid, ell_t, i]
    return ell_t, A, B, link_ctx, range_ctx


def signed_report(sch, i, ell_t, Ci, pi_val):
    """A report signed with meter i's own key -- what a corrupted meter can do."""
    msg = cat(sch.group, b'REP', sch.sid, ell_t, i, Ci, pi_val)
    return (i, ell_t, Ci, pi_val, schnorr_sign(sch.group, sch.g1, sch.rsk[i], msg))


def check(cond, msg, fails):
    print(("  PASS: " if cond else "  FAIL: ") + msg)
    if not cond:
        fails.append(msg)


# ---------------------------------------------------------------------------
# Part 1: weak Fiat-Shamir forgery (V not in the range-proof transcript)
# ---------------------------------------------------------------------------

def forge_range_proof_without_statement(sch, ctx):
    """Cheating prover: fix A, S, T1, T2 and all challenges first, then SOLVE
    for V so that the outer check holds. Uses the current (unpatched)
    transcript layout. Returns (V, v, gamma, proof), where V = g1^v hx^gamma
    and v is essentially a random field element (out of range w.h.p.)."""
    G, g1, hx, Lb = sch.group, sch.g1, sch.hx, sch.L
    gv, hv = sch.g_vec, sch.h_vec
    one, zero = G.init(ZR, 1), G.init(ZR, 0)

    aL = [G.init(ZR, 2)] + [zero] * (Lb - 1)          # deliberately NOT a bit vector
    aR = [a - one for a in aL]
    alpha, rho = G.random(ZR), G.random(ZR)
    sL = [G.random(ZR) for _ in range(Lb)]
    sR = [G.random(ZR) for _ in range(Lb)]
    A = (hx ** alpha) * vec_commit(gv, aL) * vec_commit(hv, aR)
    S = (hx ** rho) * vec_commit(gv, sL) * vec_commit(hv, sR)

    y = fs_challenge(G, b'BP-Y', *ctx, A, S)
    z = fs_challenge(G, b'BP-Z', *ctx, A, S, y)
    yp = zr_powers(G, y, Lb)
    tp = [G.init(ZR, 2 ** i) for i in range(Lb)]
    z2 = z * z

    l0 = [aL[i] - z for i in range(Lb)]
    r0 = [yp[i] * (aR[i] + z) + z2 * tp[i] for i in range(Lb)]
    r1 = [yp[i] * sR[i] for i in range(Lb)]
    t0 = inner_product(l0, r0)
    t1 = inner_product(l0, r1) + inner_product(sL, r0)
    t2 = inner_product(sL, r1)

    tau1, tau2 = G.random(ZR), G.random(ZR)
    T1 = (g1 ** t1) * (hx ** tau1)
    T2 = (g1 ** t2) * (hx ** tau2)
    xc = fs_challenge(G, b'BP-X', *ctx, A, S, T1, T2, y, z)

    l = [l0[i] + sL[i] * xc for i in range(Lb)]
    r = [r0[i] + r1[i] * xc for i in range(Lb)]
    t = inner_product(l, r)
    gamma = G.random(ZR)
    tau_x = tau1 * xc + tau2 * (xc * xc) + z2 * gamma
    mu = alpha + rho * xc

    sum_y = yp[0]
    for i in range(1, Lb):
        sum_y = sum_y + yp[i]
    delta = (z - z2) * sum_y - (z * z2) * G.init(ZR, 2 ** Lb - 1)
    v = (t0 - delta) / z2                  # the committed value is fixed only NOW
    V = (g1 ** v) * (hx ** gamma)

    y_inv_pows = zr_powers(G, one / y, Lb)
    h_prime = [hv[i] ** y_inv_pows[i] for i in range(Lb)]
    w = fs_challenge(G, b'BP-W', *ctx, A, S, T1, T2, y, z, xc, tau_x, mu, t)
    ipa_ctx = [b'BP-IPA', *ctx, A, S, T1, T2, y, z, xc, tau_x, mu, t, w]
    ipa = ipa_prove(G, gv, h_prime, g1 ** w, l, r, ipa_ctx)

    proof = {'A': A, 'S': S, 'T1': T1, 'T2': T2,
             'tau_x': tau_x, 'mu': mu, 't': t, 'ipa': ipa}
    return V, v, gamma, proof


def part1_statement_binding():
    sch = fresh(b'proof-tests-part1')
    G, g1 = sch.group, sch.g1
    i, t = 1, 0
    ell_t, A, B, lctx, rctx = contexts(sch, i, t)

    V, v, gamma, pf = forge_range_proof_without_statement(sch, rctx)
    v_int = int(v)
    where = "inside" if v_int < 2 ** L else "OUTSIDE"
    print(f"  forged commitment opens to a {v_int.bit_length()}-bit value, {where} [0, 2^{L})")

    # A complete report for corrupted meter i: the linking proof is generated
    # honestly, because the meter knows the opening (v, gamma) of the forged V.
    Cf = (g1 ** v) * (A ** sch.si[i]) * (B ** sch.ti[i])
    plink = link_prove(G, g1, sch.u, sch.h, sch.hx, A, B, lctx, sch.K[i], Cf, V,
                       (v, sch.si[i], sch.ti[i], sch.rho[i], gamma))
    Rf = signed_report(sch, i, ell_t, Cf, (V, plink, pf))

    if not sch.verify_rep(Rf):
        print("  PASS: VerifyRep rejects the forged report (V is bound into the transcript)")
        return True

    print("  FAIL: VerifyRep ACCEPTS a report whose plaintext is out of range")
    xs = [pyrandom.randint(0, 2 ** L - 1) for _ in range(N)]
    reports = [Rf] + [sch.report(j, t, xs[j - 1]) for j in range(2, N + 1)]
    T, C, d = sch.build(t, reports)
    print(f"        GoodTrans accepts the transcript: {sch.good_trans(t, T, C, d)}")
    shares = {j: sch.cert_share(j, t, T, C, d) for j in sch.Q}
    tau = sch.cert_combine(t, C, d, shares)
    print(f"        quorum certificate verifies: {sch.verify_cert(t, d, C, tau)}")
    try:
        sch.aggr_dec(t, C, tau, d)
        print("        AggrDec returned a value (unexpected)")
    except ValueError as e:
        print(f"        AggrDec fails on the certified package: {e}")
    return False


# ---------------------------------------------------------------------------
# Part 2: the proofs constrain the data (requires the patched range proof)
# ---------------------------------------------------------------------------

def part2_proofs_constrain_data():
    sch = fresh(b'proof-tests-part2')
    G, g1, hx, u, h = sch.group, sch.g1, sch.hx, sch.u, sch.h
    gv, hv = sch.g_vec, sch.h_vec
    i, t = 1, 0
    ell_t, A, B, lctx, rctx = contexts(sch, i, t)
    fails = []

    def zr(v):
        return G.init(ZR, v)

    def enc(x, j=i):                       # AOE ciphertext of x under meter j's key
        return (g1 ** zr(x)) * (A ** sch.si[j]) * (B ** sch.ti[j])

    def com(xz, gam):                      # Pedersen commitment, xz a ZR scalar
        return (g1 ** xz) * (hx ** gam)

    def lprove(Ci, Vi, wit, Ki):
        return link_prove(G, g1, u, h, hx, A, B, lctx, Ki, Ci, Vi, wit)

    def lverify(Ci, Vi, pr, Ki):
        return link_verify(G, g1, u, h, hx, A, B, lctx, Ki, Ci, Vi, pr)

    def rprove(V, x_int, gam):
        return range_prove_bp(G, g1, hx, gv, hv, V, x_int, gam, L, rctx)

    def rverify(V, pr):
        return range_verify_bp(G, g1, hx, gv, hv, L, rctx, V, pr)

    x, gam = 1234, G.random(ZR)
    Ci, Vi = enc(x), com(zr(x), gam)
    Ki = sch.K[i]
    wit = (zr(x), sch.si[i], sch.ti[i], sch.rho[i], gam)

    # ---- linking proof ----------------------------------------------------
    print("Linking proof")
    pl = lprove(Ci, Vi, wit, Ki)
    check(lverify(Ci, Vi, pl, Ki), "honest proof accepted", fails)
    check(not lverify(enc(x + 1), Vi, lprove(enc(x + 1), Vi, wit, Ki), Ki),
          "C encrypts x+1 while V commits to x: rejected", fails)
    wit_other = (zr(x), sch.si[2], sch.ti[2], sch.rho[i], gam)
    check(not lverify(enc(x, 2), Vi, lprove(enc(x, 2), Vi, wit_other, Ki), Ki),
          "C under meter 2's AOE key, checked against K_1: rejected", fails)
    check(not lverify(Ci, Vi, pl, sch.K[2]),
          "valid proof checked against another meter's K: rejected", fails)
    for idx, name in enumerate(['T1', 'T2', 'T3']):
        bad = list(pl); bad[idx] = bad[idx] * g1
        check(not lverify(Ci, Vi, tuple(bad), Ki), f"{name} altered: rejected", fails)
    for idx, name in zip(range(3, 8), ['zx', 'zs', 'zt', 'zrho', 'zgamma']):
        bad = list(pl); bad[idx] = bad[idx] + zr(1)
        check(not lverify(Ci, Vi, tuple(bad), Ki), f"{name} altered: rejected", fails)

    # ---- range proof --------------------------------------------------------
    print("Range proof")
    for xv in (0, 1, x, 2 ** L - 1):
        g_ = G.random(ZR); V = com(zr(xv), g_)
        check(rverify(V, rprove(V, xv, g_)), f"honest proof for x = {xv} accepted", fails)
    out_of_range = [("2^L", zr(2 ** L), 2 ** L),
                    ("2^L + 5", zr(2 ** L + 5), 2 ** L + 5),
                    ("-1 (i.e. p - 1)", zneg(G, zr(1)), 2 ** L - 1)]
    for label, vz, x_for_bits in out_of_range:
        g_ = G.random(ZR); V = com(vz, g_)
        check(not rverify(V, rprove(V, x_for_bits, g_)),
              f"commitment to {label}: rejected", fails)

    pr = rprove(Vi, x, gam)
    check(rverify(Vi, pr), "honest proof for the report value accepted", fails)
    check(not rverify(com(zr(x), G.random(ZR)), pr),
          "proof replayed on a different commitment: rejected", fails)

    def mutated(key):
        p2 = dict(pr)
        ipa = dict(pr['ipa']); ipa['L'] = list(ipa['L']); ipa['R'] = list(ipa['R'])
        p2['ipa'] = ipa
        if key in ('A', 'S', 'T1', 'T2'):
            p2[key] = p2[key] * g1
        elif key in ('t', 'tau_x', 'mu'):
            p2[key] = p2[key] + zr(1)
        elif key in ('a', 'b'):
            ipa[key] = ipa[key] + zr(1)
        elif key in ('L', 'R'):
            ipa[key][0] = ipa[key][0] * g1
        elif key == 'drop_ipa_round':
            ipa['L'].pop(); ipa['R'].pop()
        return p2

    for key in ('A', 'S', 'T1', 'T2', 't', 'tau_x', 'mu', 'a', 'b', 'L', 'R', 'drop_ipa_round'):
        check(not rverify(Vi, mutated(key)), f"{key} altered: rejected", fails)

    # ---- through VerifyRep, re-signed so the signature cannot mask anything --
    print("Through VerifyRep (tampered reports re-signed with the meter's own key)")
    honest = signed_report(sch, i, ell_t, Ci, (Vi, pl, pr))
    ok, tm = sch.verify_rep(honest, return_timing=True)
    check(ok and tm['link'] > 0 and tm['range'] > 0,
          "honest report: signature, linking and range checks all run and pass", fails)

    bad = signed_report(sch, i, ell_t, Ci * g1, (Vi, pl, pr))
    ok, tm = sch.verify_rep(bad, return_timing=True)
    check(not ok and tm['link'] > 0 and tm['range'] == 0.0,
          "altered ciphertext, re-signed: stopped by the linking proof", fails)

    big, g_ = 2 ** L, G.random(ZR)
    Cb, Vb = enc(big), com(zr(big), g_)
    plb = lprove(Cb, Vb, (zr(big), sch.si[i], sch.ti[i], sch.rho[i], g_), Ki)
    check(lverify(Cb, Vb, plb, Ki),
          "linking proof alone accepts x = 2^L (expected: it does not check the range)", fails)
    Rb = signed_report(sch, i, ell_t, Cb, (Vb, plb, rprove(Vb, big, g_)))
    ok, tm = sch.verify_rep(Rb, return_timing=True)
    check(not ok and tm['range'] > 0,
          "x = 2^L with valid signature and linking proof: stopped by the range proof", fails)

    return fails


if __name__ == '__main__':
    pyrandom.seed(7)
    print("Part 1: is V bound into the range-proof transcript?")
    bound = part1_statement_binding()

    if not PATCHED:
        print("\nPart 2 skipped: apply the range-proof patch (range_prove_bp takes V) and rerun.")
        raise SystemExit(1)

    print("\nPart 2: do the proofs constrain the data?")
    fails = part2_proofs_constrain_data()
    if not bound:
        fails.append("statement binding (Part 1)")
    print("\nALL PASSED" if not fails else f"\n{len(fails)} FAILED")
    raise SystemExit(1 if fails else 0)