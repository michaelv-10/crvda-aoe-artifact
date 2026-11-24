"""
CRVDA-AOE reference implementation (Charm-Crypto)
==================================================
"""

import csv
import hashlib
import math
import os
import platform
import random as pyrandom
import time

from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR, pair


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def to_bytes(group, obj):
    """Canonical, recursive byte encoding of a value for hashing/signing."""
    if isinstance(obj, bytes):
        return obj
    if isinstance(obj, str):
        return obj.encode()
    if isinstance(obj, int):
        return str(obj).encode()
    if isinstance(obj, (tuple, list)):
        return b'|'.join(to_bytes(group, o) for o in obj)
    if isinstance(obj, dict):
        return b'|'.join(to_bytes(group, obj[k]) for k in sorted(obj.keys(), key=str))
    try:
        return group.serialize(obj)  # ZR / G1 / G2 / GT element
    except Exception:
        return str(obj).encode()


def cat(group, *parts):
    """Domain-separated concatenation of heterogeneous parts."""
    return b'||'.join(to_bytes(group, p) for p in parts)


def fs_challenge(group, *parts):
    """H_FS : {0,1}* -> Z_p  (programmable RO in the security proofs)."""
    digest = hashlib.sha256(cat(group, *parts)).digest()
    val = int.from_bytes(digest, 'big')
    return group.init(ZR, val)


def hd_digest(group, *parts):
    """H_D : {0,1}* -> {0,1}^256, collision-resistant, raw bytes output."""
    return hashlib.sha256(cat(group, *parts)).digest()


def hash_to_g1(group, tag: bytes, *parts):
    """Domain-separated hash-to-group, used to instantiate H1, H2, HC, HX,
    and the Bulletproofs vector generators g_vec / h_vec."""
    return group.hash(cat(group, tag, *parts), G1)


def zneg(group, x):
    """-x mod p for a ZR scalar x."""
    return group.init(ZR, 0) - x


def random_nonzero(group):
    """Uniform NON-ZERO scalar."""
    zero = group.init(ZR, 0)
    while True:
        x = group.random(ZR)
        if x != zero:
            return x


def vec_commit(gens, exps):
    """prod_i gens[i]^exps[i]  (Pedersen vector commitment)."""
    acc = gens[0] ** exps[0]
    for i in range(1, len(gens)):
        acc = acc * (gens[i] ** exps[i])
    return acc


def zr_powers(group, base, count):
    """[base^0, base^1, ..., base^(count-1)] as ZR elements, built by
    repeated multiplication (avoids relying on ZR ** int semantics)."""
    one = group.init(ZR, 1)
    pows = [one]
    for _ in range(1, count):
        pows.append(pows[-1] * base)
    return pows


def inner_product(vec_a, vec_b):
    """<a,b> for two equal-length lists of ZR elements."""
    acc = vec_a[0] * vec_b[0]
    for i in range(1, len(vec_a)):
        acc = acc + vec_a[i] * vec_b[i]
    return acc


# ---------------------------------------------------------------------------
# Report-signature scheme: Fiat-Shamir Schnorr over G1, (R, z) form
# The signature is one G1 element R and one scalar z, as in
# |sigma| = |G1| + |Zp|.
# ---------------------------------------------------------------------------

def schnorr_keygen(group, g1):
    rsk = group.random(ZR)
    rvk = g1 ** rsk
    return rsk, rvk


def schnorr_sign(group, g1, rsk, message: bytes):
    k = group.random(ZR)
    R = g1 ** k
    c = fs_challenge(group, b'SCHNORR', message, R)    # c = H(m, R)
    z = k + rsk * c
    return (R, z)


def schnorr_verify(group, g1, rvk, message: bytes, sig):
    R, z = sig
    c = fs_challenge(group, b'SCHNORR', message, R)    # recompute c = H(m, R)
    return (g1 ** z) == R * (rvk ** c)                 # g^z = R * pk^c


# ---------------------------------------------------------------------------
# Generalized Schnorr linking proof 
# ---------------------------------------------------------------------------

def link_prove(group, g1, u, h, hx, A, B, ctx, Ki, Ci, Vi, witness):
    x, s, tprime, rho, gamma = witness
    ax = group.random(ZR)
    as_ = group.random(ZR)
    at = group.random(ZR)
    arho = group.random(ZR)
    agamma = group.random(ZR)

    T1 = (g1 ** as_) * (u ** at) * (h ** arho)          # Eq. 11
    T2 = (g1 ** ax) * (A ** as_) * (B ** at)             # Eq. 12
    T3 = (g1 ** ax) * (hx ** agamma)                     # Eq. 13

    c = fs_challenge(group, b'VAL', *ctx, Ki, Ci, Vi, T1, T2, T3)  # Eq. 14

    zx = ax + c * x
    zs = as_ + c * s
    zt = at + c * tprime
    zrho = arho + c * rho
    zgamma = agamma + c * gamma

    return (T1, T2, T3, zx, zs, zt, zrho, zgamma)


def link_verify(group, g1, u, h, hx, A, B, ctx, Ki, Ci, Vi, proof):
    T1, T2, T3, zx, zs, zt, zrho, zgamma = proof
    c = fs_challenge(group, b'VAL', *ctx, Ki, Ci, Vi, T1, T2, T3)   
    if (g1 ** zs) * (u ** zt) * (h ** zrho) != T1 * (Ki ** c):      
        return False
    if (g1 ** zx) * (A ** zs) * (B ** zt) != T2 * (Ci ** c):        
        return False
    if (g1 ** zx) * (hx ** zgamma) != T3 * (Vi ** c):               
        return False
    return True


# ---------------------------------------------------------------------------
# Bulletproofs: improved inner-product argument
# ---------------------------------------------------------------------------

def ipa_prove(group, g, h, u_prime, a, b, ctx):
    Ls, Rs = [], []
    round_ctx = list(ctx)
    g, h, a, b = list(g), list(h), list(a), list(b)

    while len(a) > 1:
        n2 = len(a) // 2
        aL_, aR_ = a[:n2], a[n2:]
        bL_, bR_ = b[:n2], b[n2:]
        gL, gR = g[:n2], g[n2:]
        hL, hR = h[:n2], h[n2:]

        cL = inner_product(aL_, bR_)                                  
        cR = inner_product(aR_, bL_)                                  
        L = vec_commit(gR, aL_) * vec_commit(hL, bR_) * (u_prime ** cL)  
        R = vec_commit(gL, aR_) * vec_commit(hR, bL_) * (u_prime ** cR)  

        x = fs_challenge(group, b'BP-IPA-X', *round_ctx, len(Ls), L, R)
        x_inv = group.init(ZR, 1) / x

        g = [gL[i] ** x_inv * gR[i] ** x for i in range(n2)]         
        h = [hL[i] ** x * hR[i] ** x_inv for i in range(n2)]         
        a = [aL_[i] * x + aR_[i] * x_inv for i in range(n2)]          
        b = [bL_[i] * x_inv + bR_[i] * x for i in range(n2)]         

        Ls.append(L)
        Rs.append(R)
        round_ctx = round_ctx + [L, R]

    return {'L': Ls, 'R': Rs, 'a': a[0], 'b': b[0]}


def ipa_verify(group, g, h, u_prime, P, ctx, proof):
    Ls, Rs, a_final, b_final = proof['L'], proof['R'], proof['a'], proof['b']
    round_ctx = list(ctx)
    cur_g, cur_h, cur_P = list(g), list(h), P

    for j in range(len(Ls)):
        L, R = Ls[j], Rs[j]
        x = fs_challenge(group, b'BP-IPA-X', *round_ctx, j, L, R)
        x_inv = group.init(ZR, 1) / x
        n2 = len(cur_g) // 2
        gL, gR = cur_g[:n2], cur_g[n2:]
        hL, hR = cur_h[:n2], cur_h[n2:]

        cur_g = [gL[i] ** x_inv * gR[i] ** x for i in range(n2)]
        cur_h = [hL[i] ** x * hR[i] ** x_inv for i in range(n2)]
        cur_P = (L ** (x * x)) * cur_P * (R ** (x_inv * x_inv))       # Eq. 30
        round_ctx = round_ctx + [L, R]

    rhs = (cur_g[0] ** a_final) * (cur_h[0] ** b_final) * (u_prime ** (a_final * b_final))
    return cur_P == rhs                                               # Eq. 14


# ---------------------------------------------------------------------------
# Bulletproofs: single-value range proof
# ---------------------------------------------------------------------------

def _bp_statement_ctx(ctx, V, L: int):
    return [*ctx, b'BP-STMT', L, V]


def range_prove_bp(group, g1, hx, g_vec, h_vec, V, x_int: int, gamma, L: int, ctx):
    assert (L & (L - 1)) == 0 and L > 0, "Bulletproofs requires L to be a power of 2"
    ctx = _bp_statement_ctx(ctx, V, L)

    one = group.init(ZR, 1)

    aL = [group.init(ZR, (x_int >> i) & 1) for i in range(L)]         # Eq. 36
    aR = [aL[i] - one for i in range(L)]                              # Eq. 37

    alpha = group.random(ZR)
    A = (hx ** alpha) * vec_commit(g_vec, aL) * vec_commit(h_vec, aR)  # Eq. 39

    sL = [group.random(ZR) for _ in range(L)]
    sR = [group.random(ZR) for _ in range(L)]
    rho = group.random(ZR)
    S = (hx ** rho) * vec_commit(g_vec, sL) * vec_commit(h_vec, sR)    # Eq. 42

    y = fs_challenge(group, b'BP-Y', *ctx, A, S)
    z = fs_challenge(group, b'BP-Z', *ctx, A, S, y)

    y_pows = zr_powers(group, y, L)
    two_pows = [group.init(ZR, 2 ** i) for i in range(L)]

    l0 = [aL[i] - z for i in range(L)]
    l1 = sL
    r0 = [y_pows[i] * (aR[i] + z) + (z * z) * two_pows[i] for i in range(L)]
    r1 = [y_pows[i] * sR[i] for i in range(L)]

    t1 = inner_product(l0, r1) + inner_product(l1, r0)
    t2 = inner_product(l1, r1)

    tau1 = group.random(ZR)
    tau2 = group.random(ZR)
    T1 = (g1 ** t1) * (hx ** tau1)                                     # Eq. 48
    T2 = (g1 ** t2) * (hx ** tau2)

    xc = fs_challenge(group, b'BP-X', *ctx, A, S, T1, T2, y, z)

    l = [l0[i] + l1[i] * xc for i in range(L)]                        # Eq. 55
    r = [r0[i] + r1[i] * xc for i in range(L)]                        # Eq. 56
    t = inner_product(l, r)                                           # Eq. 54
    tau_x = tau1 * xc + tau2 * (xc * xc) + (z * z) * gamma            # Eq. 52
    mu = alpha + rho * xc                                             # Eq. 53

    # h'_i = h_i^{y^{-i}}
    y_inv = one / y
    y_inv_pows = zr_powers(group, y_inv, L)
    h_prime = [h_vec[i] ** y_inv_pows[i] for i in range(L)]

    # Merge <l,r>=t into the u-base per Protocol 1's embedding step
    # (published Eqs. 3-6: P' = P.u^{x.c}, recurse on u^x; here u = g1,
    # reused, and the challenge is called w instead of x to avoid a name
    # clash with the range proof's own x). Then run the recursive
    # inner-product argument (Protocol 2) on (g_vec, h_prime, g1^w; l, r).
    w = fs_challenge(group, b'BP-W', *ctx, A, S, T1, T2, y, z, xc, tau_x, mu, t)
    u_prime = g1 ** w

    ipa_ctx = [b'BP-IPA', *ctx, A, S, T1, T2, y, z, xc, tau_x, mu, t, w]
    ipa_proof = ipa_prove(group, g_vec, h_prime, u_prime, l, r, ipa_ctx)

    return {'A': A, 'S': S, 'T1': T1, 'T2': T2,
            'tau_x': tau_x, 'mu': mu, 't': t, 'ipa': ipa_proof}


def range_verify_bp(group, g1, hx, g_vec, h_vec, L: int, ctx, V, proof):
    rounds = L.bit_length() - 1
    if len(proof['ipa']['L']) != rounds or len(proof['ipa']['R']) != rounds:
        return False
    ctx = _bp_statement_ctx(ctx, V, L)       # same statement binding as the prover

    one = group.init(ZR, 1)
    A, S, T1, T2 = proof['A'], proof['S'], proof['T1'], proof['T2']
    tau_x, mu, t = proof['tau_x'], proof['mu'], proof['t']

    y = fs_challenge(group, b'BP-Y', *ctx, A, S)
    z = fs_challenge(group, b'BP-Z', *ctx, A, S, y)

    y_pows = zr_powers(group, y, L)
    two_pows = [group.init(ZR, 2 ** i) for i in range(L)]

    sum_y = y_pows[0]
    for i in range(1, L):
        sum_y = sum_y + y_pows[i]
    sum_2 = group.init(ZR, (2 ** L) - 1)

    xc = fs_challenge(group, b'BP-X', *ctx, A, S, T1, T2, y, z)

    # --- outer check: t is consistent with V, T1, T2 ---
    z2 = z * z
    rhs_exp = z * sum_y - z2 * sum_y - (z * z2) * sum_2
    lhs1 = (g1 ** t) * (hx ** tau_x)
    rhs1 = (g1 ** rhs_exp) * (V ** z2) * (T1 ** xc) * (T2 ** (xc * xc))
    if lhs1 != rhs1:
        return False

    # --- fold h into h' = h_i^{y^{-i}} ---
    y_inv = one / y
    y_inv_pows = zr_powers(group, y_inv, L)
    h_prime = [h_vec[i] ** y_inv_pows[i] for i in range(L)]

    # --- verifier-derived P ---
    neg_z = zneg(group, z)
    P = A * (S ** xc) * vec_commit(g_vec, [neg_z] * L) \
        * vec_commit(h_prime, [z * y_pows[i] + z2 * two_pows[i] for i in range(L)])

    # --- fold t and mu in via Protocol 1's embedding step (public input
    #     g, h', g1, P*h^-mu, t per Sec. 4.2), then run Protocol 2 (the
    #     inner-product argument) check ---
    w = fs_challenge(group, b'BP-W', *ctx, A, S, T1, T2, y, z, xc, tau_x, mu, t)
    u_prime = g1 ** w
    P_target = P * (hx ** zneg(group, mu)) * (g1 ** (w * t))

    ipa_ctx = [b'BP-IPA', *ctx, A, S, T1, T2, y, z, xc, tau_x, mu, t, w]
    return ipa_verify(group, g_vec, h_prime, u_prime, P_target, ipa_ctx, proof['ipa'])


# ---------------------------------------------------------------------------
# Bounded discrete log (baby-step giant-step), used by AggrDec (Sec. VIII)
# ---------------------------------------------------------------------------

class BoundedDLog:
    def __init__(self, group, g1, upper_bound: int):
        self.group = group
        self.g1 = g1
        self.upper_bound = upper_bound
        self.m = math.ceil(math.sqrt(max(upper_bound, 1))) + 1

        table = {}
        acc = g1 ** group.init(ZR, 0)  # identity element (g1^0)
        table[group.serialize(acc)] = 0
        cur = acc
        for j in range(1, self.m):
            cur = cur * g1
            table[group.serialize(cur)] = j
        self.table = table

        gm = g1
        for _ in range(self.m - 1):
            gm = gm * g1
        self.giant_step = gm ** zneg(group, group.init(ZR, 1))

    def solve(self, h):
        cur = h
        for i in range(self.m + 1):
            key = self.group.serialize(cur)
            if key in self.table:
                x = i * self.m + self.table[key]
                if x <= self.upper_bound:
                    return x
            cur = cur * self.giant_step
        raise ValueError("discrete log not found in range [0, upper_bound]")


# ---------------------------------------------------------------------------
# Main construction  (Sec. VIII)
# ---------------------------------------------------------------------------

class CRVDA_AOE:
    def __init__(self, curve: str = 'BN254'):
        self.group = PairingGroup(curve)

    # ---- Setup(1^lambda, n, k, L) ---------------------------

    def setup(self, n: int, k: int, L: int, sid: bytes = b'sid-0'):
        group = self.group
        g1 = group.random(G1)
        g2 = group.random(G2)
        p = group.order()

        U = list(range(1, n + 1))
        rid = hd_digest(group, b'ROSTER', *U)

        if n * ((2 ** L) - 1) >= p:
            raise ValueError("no-wrap bound n(2^L - 1) < p (Eq. 3) violated for this (n, L)")
        if not (0 <= k <= n - 2):
            raise ValueError("the adversary bound of Sec. VI-B requires 0 <= k <= n - 2")
        if not (L > 0 and (L & (L - 1)) == 0):
            raise ValueError("the Bulletproof range proof requires L to be a power of 2")

        # BJL AOE keys, s0 = -sum si, t0 = -sum ti
        si = {i: group.random(ZR) for i in U}
        ti = {i: group.random(ZR) for i in U}
        s0 = group.init(ZR, 0)
        t0 = group.init(ZR, 0)
        for i in U:
            s0 = s0 - si[i]
            t0 = t0 - ti[i]
        S0 = g1 ** s0
        T0 = g1 ** t0

        # hidden registration commitments. (eta, delta) are LOCAL ONLY
        eta = random_nonzero(group)
        delta = random_nonzero(group)
        u = g1 ** eta
        h = g1 ** delta
        rho = {}
        K = {}
        for i in U:
            rho[i] = group.random(ZR)
            K[i] = (g1 ** si[i]) * (u ** ti[i]) * (h ** rho[i])
        del eta, delta

        # report-signature keys
        rsk = {}
        rvk = {}
        for i in U:
            rsk[i], rvk[i] = schnorr_keygen(group, g1)

        # certification quorum Q, |Q| = k+1 (fixed choice)
        Q = list(range(1, k + 2))
        z = {j: group.random(ZR) for j in Q}
        W = {j: g2 ** z[j] for j in Q}
        WQ = None
        for j in Q:
            WQ = W[j] if WQ is None else WQ * W[j]

        # range-proof generators. hx is the scalar generator used by
        # Vi = g1^x hx^gamma. g_vec/h_vec are the
        # Bulletproofs vector generators; g1 itself doubles as
        # the inner-product argument's 'u' base.
        hx = hash_to_g1(group, b'RANGE-GEN')
        g_vec = [hash_to_g1(group, b'BP-G', idx) for idx in range(L)]
        h_vec = [hash_to_g1(group, b'BP-H', idx) for idx in range(L)]

        self.n, self.k, self.L, self.sid, self.rid = n, k, L, sid, rid
        self.g1, self.g2 = g1, g2
        self.si, self.ti, self.s0, self.t0 = si, ti, s0, t0
        self.S0, self.T0 = S0, T0
        self.u, self.h, self.rho, self.K = u, h, rho, K
        self.rsk, self.rvk = rsk, rvk
        self.Q, self.z, self.W, self.WQ = Q, z, W, WQ
        self.hx, self.g_vec, self.h_vec = hx, g_vec, h_vec

        self._report_cache = {}   # (i, ell_t) -> Ri_t, encrypt-once cache
        self._bsgs = None

    # ---- round label ell_t = ROUND || sid || t || rid -------------------

    def ell(self, t):
        return cat(self.group, b'ROUND', self.sid, t, self.rid)

    # ---- Report(i, t, x_it)  (Sec. VIII) ----------------------------------

    def report(self, i: int, t, x_it: int, return_timing: bool = False):
        if i not in self.si:
            raise ValueError(f"unknown meter identity {i!r}")
        ell_t = self.ell(t)
        cache_key = (i, ell_t)
        if cache_key in self._report_cache:
            cached = self._report_cache[cache_key]
            if return_timing:
                return cached, {'encrypt': 0.0, 'commit': 0.0, 'range': 0.0, 'link': 0.0,
                                'proofgen': 0.0, 'sign': 0.0}
            return cached

        if not (0 <= x_it < 2 ** self.L):
            raise ValueError("Report requires 0 <= x < 2^L (Sec. VIII)")

        group, g1, hx, u, h = self.group, self.g1, self.hx, self.u, self.h

        # --- sub-phase 1: encryption of the raw value ---
        t0 = time.perf_counter()
        A = hash_to_g1(group, b'H1', ell_t)
        B = hash_to_g1(group, b'H2', ell_t)
        # Ci_t = g1^x H1(ell)^si H2(ell)^ti  (Sec. IV, Eq. 1)
        Ci_t = (g1 ** group.init(ZR, x_it)) * (A ** self.si[i]) * (B ** self.ti[i])
        t_encrypt = time.perf_counter() - t0

        # --- sub-phase 2: proof generation (commitment + range + linking),
        #     timed per component ---
        t0 = time.perf_counter()
        # Vi_t = g1^x hx^gamma -- gamma is a single fresh scalar;
        # the Bulletproofs range proof does not decompose it per bit.
        gamma_it = group.random(ZR)
        Vi_t = (g1 ** group.init(ZR, x_it)) * (hx ** gamma_it)
        t_commit = time.perf_counter() - t0

        t0 = time.perf_counter()
        range_ctx = [b'RANGE-CTX', self.sid, ell_t, i]
        pi_range = range_prove_bp(group, g1, hx, self.g_vec, self.h_vec,
                                   Vi_t, x_it, gamma_it, self.L, range_ctx)
        t_range = time.perf_counter() - t0

        t0 = time.perf_counter()
        link_ctx = [self.sid, ell_t, i]
        witness = (group.init(ZR, x_it), self.si[i], self.ti[i], self.rho[i], gamma_it)
        pi_link = link_prove(group, g1, u, h, hx, A, B, link_ctx,
                              self.K[i], Ci_t, Vi_t, witness)
        t_link = time.perf_counter() - t0
        t_proofgen = t_commit + t_range + t_link

        # --- sub-phase 3: signing ---
        t0 = time.perf_counter()
        pi_val = (Vi_t, pi_link, pi_range)
        # mi_t = REP || sid || ell_t || i || Ci_t || pi_val_i_t
        msg = cat(group, b'REP', self.sid, ell_t, i, Ci_t, pi_val)
        sigma_i_t = schnorr_sign(group, g1, self.rsk[i], msg)
        t_sign = time.perf_counter() - t0

        Ri_t = (i, ell_t, Ci_t, pi_val, sigma_i_t)
        self._report_cache[cache_key] = Ri_t

        if return_timing:
            return Ri_t, {'encrypt': t_encrypt, 'commit': t_commit, 'range': t_range,
                          'link': t_link, 'proofgen': t_proofgen, 'sign': t_sign}
        return Ri_t

    # ---- VerifyRep(Ri_t) --------------------------------------

    def _report_well_formed(self, Ri_t):
        try:
            i, ell_t, Ci_t, pi_val, sigma = Ri_t
            Vi_t, pi_link, pi_range = pi_val
        except (TypeError, ValueError):
            return False
        if isinstance(i, bool) or not isinstance(i, int) or not (1 <= i <= self.n):
            return False
        if not isinstance(ell_t, bytes):
            return False
        head = b'ROUND||' + to_bytes(self.group, self.sid) + b'||'
        tail = b'||' + to_bytes(self.group, self.rid)
        if not (ell_t.startswith(head) and ell_t.endswith(tail)):
            return False
        return (isinstance(pi_link, tuple) and len(pi_link) == 8
                and isinstance(sigma, tuple) and len(sigma) == 2
                and isinstance(pi_range, dict))

    def verify_rep(self, Ri_t, return_timing: bool = False):
        timing = {'sig': 0.0, 'label': 0.0, 'link': 0.0, 'range': 0.0}
        ok = False
        if self._report_well_formed(Ri_t):
            try:
                ok = self._verify_rep_checks(Ri_t, timing)
            except Exception:
                ok = False   # a malformed element or proof rejects; it must not crash the verifier
        return (ok, timing) if return_timing else ok

    def _verify_rep_checks(self, Ri_t, timing):
        i, ell_t, Ci_t, pi_val, sigma = Ri_t
        Vi_t, pi_link, pi_range = pi_val
        group = self.group

        t0 = time.perf_counter()
        msg = cat(group, b'REP', self.sid, ell_t, i, Ci_t, pi_val)
        sig_ok = schnorr_verify(group, self.g1, self.rvk[i], msg, sigma)
        timing['sig'] = time.perf_counter() - t0
        if not sig_ok:
            return False

        t0 = time.perf_counter()
        A = hash_to_g1(group, b'H1', ell_t)      # label hashes needed by the linking proof
        B = hash_to_g1(group, b'H2', ell_t)
        timing['label'] = time.perf_counter() - t0
        link_ctx = [self.sid, ell_t, i]
        t0 = time.perf_counter()
        link_ok = link_verify(group, self.g1, self.u, self.h, self.hx, A, B,
                               link_ctx, self.K[i], Ci_t, Vi_t, pi_link)
        timing['link'] = time.perf_counter() - t0
        if not link_ok:
            return False

        range_ctx = [b'RANGE-CTX', self.sid, ell_t, i]
        t0 = time.perf_counter()
        range_ok = range_verify_bp(group, self.g1, self.hx, self.g_vec, self.h_vec,
                                    self.L, range_ctx, Vi_t, pi_range)
        timing['range'] = time.perf_counter() - t0
        return bool(range_ok)

    # ---- Build(t, {Ri_t}) -------------------------------------

    def build(self, t, reports):
        ell_t = self.ell(t)
        reports_sorted = sorted(reports, key=lambda r: r[0])
        Ct = reports_sorted[0][2]
        for r in reports_sorted[1:]:
            Ct = Ct * r[2]
        dt = hd_digest(self.group, b'TRANS', self.sid, ell_t, reports_sorted)
        return reports_sorted, Ct, dt

    # ---- GoodTrans(t, T, C, d) ---------------------------------

    def good_trans(self, t, T, C, d, return_timing: bool = False):
        timing = {'reportcheck': 0.0, 'aggcheck': 0.0, 'digest': 0.0,
                  'rep_sig': 0.0, 'rep_label': 0.0, 'rep_link': 0.0, 'rep_range': 0.0,
                  'rep_other': 0.0}

        t0 = time.perf_counter()
        ell_t = self.ell(t)
        ok = True
        try:
            if len(T) != self.n:
                ok = False
            else:
                ids = [r[0] for r in T]
                if ids != list(range(1, self.n + 1)):
                    ok = False
                else:
                    for r in T:
                        if r[1] != ell_t:
                            ok = False
                            break
                        if return_timing:
                            r_ok, rt = self.verify_rep(r, return_timing=True)
                            timing['rep_sig'] += rt['sig']
                            timing['rep_label'] += rt['label']
                            timing['rep_link'] += rt['link']
                            timing['rep_range'] += rt['range']
                        else:
                            r_ok = self.verify_rep(r)
                        if not r_ok:
                            ok = False
                            break
        except Exception:
            ok = False   # a malformed transcript is rejected, never raised
        timing['reportcheck'] = time.perf_counter() - t0
        timing['rep_other'] = max(0.0, timing['reportcheck'] - timing['rep_sig'] - timing['rep_label']
                                  - timing['rep_link'] - timing['rep_range'])
        if not ok:
            return (False, timing) if return_timing else False

        t0 = time.perf_counter()
        try:
            C_check = T[0][2]
            for r in T[1:]:
                C_check = C_check * r[2]
            agg_ok = (C_check == C)
        except Exception:
            agg_ok = False
        timing['aggcheck'] = time.perf_counter() - t0
        if not agg_ok:
            return (False, timing) if return_timing else False

        t0 = time.perf_counter()
        try:
            digest_ok = (hd_digest(self.group, b'TRANS', self.sid, ell_t, T) == d)
        except Exception:
            digest_ok = False
        timing['digest'] = time.perf_counter() - t0
        if not digest_ok:
            return (False, timing) if return_timing else False

        return (True, timing) if return_timing else True

    # ---- CertShare / CertCombine / VerifyCert  -------------

    def _cert_message_hash_ell(self, ell_t, C, d):
        M = cat(self.group, b'AGG', self.sid, ell_t, d, C)   # M_t
        return hash_to_g1(self.group, b'HC', b'CERT', M)     # HC(CERT || M_t)

    def _cert_message_hash(self, t, C, d):
        return self._cert_message_hash_ell(self.ell(t), C, d)

    def cert_share(self, j: int, t, T, C, d, return_timing: bool = False):
        if j not in self.z:
            raise ValueError(f"{j} is not a member of the certification set Q")
        if return_timing:
            ok, timing = self.good_trans(t, T, C, d, return_timing=True)
            if not ok:
                raise ValueError("candidate transcript failed GoodTrans")
            t0 = time.perf_counter()
            Hcm = self._cert_message_hash(t, C, d)
            share = Hcm ** self.z[j]
            timing['bls'] = time.perf_counter() - t0
            return share, timing

        if not self.good_trans(t, T, C, d):
            raise ValueError("candidate transcript failed GoodTrans")
        Hcm = self._cert_message_hash(t, C, d)
        return Hcm ** self.z[j]

    def cert_combine(self, t, C, d, shares: dict, return_timing: bool = False):
        t0 = time.perf_counter()
        Hcm = self._cert_message_hash(t, C, d)
        t_hash = time.perf_counter() - t0
        for j in self.Q:
            if j not in shares:
                raise ValueError(f"missing certification share from quorum member {j}")
            if pair(shares[j], self.g2) != pair(Hcm, self.W[j]):
                raise ValueError(f"certification share from quorum member {j} failed verification")
        t_checks = time.perf_counter() - t0

        t0 = time.perf_counter()
        tau = shares[self.Q[0]]
        for j in self.Q[1:]:
            tau = tau * shares[j]
        t_mult = time.perf_counter() - t0

        if return_timing:
            # 'sharechecks' includes the one hash-to-G1 ('hash'); the k+1
            # pairing checks alone are sharechecks - hash.
            return tau, {'sharechecks': t_checks, 'hash': t_hash, 'multiply': t_mult}
        return tau

    def verify_cert_ell(self, ell_t, d, C, tau) -> bool:
        """VerifyCert(Gamma_t): Gamma_t carries ell_t, so neither the
        round number nor rid is needed here."""
        Hcm = self._cert_message_hash_ell(ell_t, C, d)
        return pair(tau, self.g2) == pair(Hcm, self.WQ)

    def verify_cert(self, t, d, C, tau) -> bool:
        return self.verify_cert_ell(self.ell(t), d, C, tau)

    # ---- AggrDec(Gamma_t) ---------------------------------------

    def build_bsgs(self):
        """Bounded-discrete-log precomputation: baby-step giant-step
        over [0, n(2^L - 1)] -- a table of m = ceil(sqrt(bound)) + 1 baby
        steps g1^0..g1^(m-1) plus one giant-step factor. The table depends
        only on (n, L), not on the round, so it is built ONCE after Setup
        and reused for every round; its cost is therefore reported
        separately ('bsgs_precompute') and is NOT part of the per-round DC
        time."""
        bound = self.n * ((2 ** self.L) - 1)
        self._bsgs = BoundedDLog(self.group, self.g1, bound)

    def bsgs_info(self):
        """(search bound, baby-step table entries)"""
        return self.n * ((2 ** self.L) - 1), self._bsgs.m

    def _aggr_dec_ell(self, ell_t, C, tau, d, return_timing: bool = False):
        """AggrDec(Gamma_t) on the label carried by Gamma_t.
        return_timing=True additionally returns the three parts the per-round
        DC cost consists of: 'certcheck' (the VerifyCert gate the definition
        requires before decrypting), 'mask' (computing Z_t), and 'dlog' (the
        bounded discrete-log solve). Any lazy table construction happens
        before the 'dlog' timer starts."""
        timing = {'certcheck': 0.0, 'mask': 0.0, 'dlog': 0.0}

        t0 = time.perf_counter()
        cert_ok = self.verify_cert_ell(ell_t, d, C, tau)
        timing['certcheck'] = time.perf_counter() - t0
        if not cert_ok:
            raise ValueError("invalid certificate")

        t0 = time.perf_counter()
        A = hash_to_g1(self.group, b'H1', ell_t)
        B = hash_to_g1(self.group, b'H2', ell_t)
        Zt = (A ** self.s0) * (B ** self.t0)
        CtZt = C * Zt
        timing['mask'] = time.perf_counter() - t0

        if self._bsgs is None:
            self.build_bsgs()
        t0 = time.perf_counter()
        Xt = self._bsgs.solve(CtZt)
        timing['dlog'] = time.perf_counter() - t0

        if return_timing:
            return Xt, Zt, timing
        return Xt, Zt

    def aggr_dec(self, t, C, tau, d, return_timing: bool = False):
        return self._aggr_dec_ell(self.ell(t), C, tau, d, return_timing)

    # ---- DecProve: public aggregate-recovery proof --------------

    def _recovery_prove_ell(self, ell_t, d, C, Xt, Zt):
        group, g1 = self.group, self.g1
        A = hash_to_g1(group, b'H1', ell_t)
        B = hash_to_g1(group, b'H2', ell_t)

        a = group.random(ZR)
        b = group.random(ZR)
        D1 = g1 ** a
        D2 = g1 ** b
        D3 = (A ** a) * (B ** b)

        cd = fs_challenge(group, b'DEC', self.sid, ell_t, d, C, Xt, Zt, D1, D2, D3)
        ys = a + cd * self.s0
        yt = b + cd * self.t0
        return (D1, D2, D3, ys, yt)

    def recovery_prove(self, t, d, C, Xt, Zt):
        return self._recovery_prove_ell(self.ell(t), d, C, Xt, Zt)

    def _recovery_verify_ell(self, ell_t, d, C, Xt, Zt, proof) -> bool:
        try:
            group, g1 = self.group, self.g1
            A = hash_to_g1(group, b'H1', ell_t)
            B = hash_to_g1(group, b'H2', ell_t)
            D1, D2, D3, ys, yt = proof

            cd = fs_challenge(group, b'DEC', self.sid, ell_t, d, C, Xt, Zt, D1, D2, D3)

            if (g1 ** ys) != D1 * (self.S0 ** cd):          
                return False
            if (g1 ** yt) != D2 * (self.T0 ** cd):         
                return False
            if (A ** ys) * (B ** yt) != D3 * (Zt ** cd):    
                return False
            if (g1 ** group.init(ZR, Xt)) != C * Zt:        
                return False
            if not (0 <= Xt <= self.n * ((2 ** self.L) - 1)):
                return False
            return True
        except Exception:
            return False   # a malformed proof rejects

    def recovery_verify(self, t, d, C, Xt, Zt, proof) -> bool:
        return self._recovery_verify_ell(self.ell(t), d, C, Xt, Zt, proof)

    def verify_omega(self, Omega, return_timing: bool = False):
        timing = {'cert': 0.0, 'recovery': 0.0}
        try:
            Gamma, Xt, Zt, pi_dec = Omega
            ell_t, d, C, tau = Gamma

            t0 = time.perf_counter()
            cert_ok = self.verify_cert_ell(ell_t, d, C, tau)
            timing['cert'] = time.perf_counter() - t0
            if not cert_ok:
                return (False, timing) if return_timing else False

            t0 = time.perf_counter()
            rec_ok = self._recovery_verify_ell(ell_t, d, C, Xt, Zt, pi_dec)
            timing['recovery'] = time.perf_counter() - t0
        except Exception:
            return (False, timing) if return_timing else False
        return (rec_ok, timing) if return_timing else rec_ok

    def verify(self, t, Gamma_t, Xt, Zt, pi_dec, return_timing: bool = False):
        """Round-number form of verify_omega, with Gamma_t given as
        (d, C, tau); used by the benchmark harness."""
        d, C, tau = Gamma_t
        return self.verify_omega(((self.ell(t), d, C, tau), Xt, Zt, pi_dec), return_timing)

    # ---- the definition's own objects Gamma_t and Omega_t -------
    # These take the label from the object, as the definition does, so a DC or
    # a public verifier needs neither rid nor the round number.

    def make_gamma(self, t, C, d, tau):
        """Gamma_t = (ell_t, d_t, C_t, tau_t)."""
        return (self.ell(t), d, C, tau)

    def cert_combine_gamma(self, t, C, d, shares):
        """CertCombine as defined: outputs Gamma_t."""
        return self.make_gamma(t, C, d, self.cert_combine(t, C, d, shares))

    def verify_gamma(self, Gamma):
        """VerifyCert(Gamma_t)."""
        try:
            ell_t, d, C, tau = Gamma
            return bool(self.verify_cert_ell(ell_t, d, C, tau))
        except Exception:
            return False

    def aggr_dec_gamma(self, Gamma, return_timing: bool = False):
        """AggrDec(Gamma_t) -> (X_t, Z_t)."""
        ell_t, d, C, tau = Gamma
        return self._aggr_dec_ell(ell_t, C, tau, d, return_timing)

    def dec_prove(self, Gamma, Xt, Zt):
        """DecProve -> pi_dec."""
        ell_t, d, C, tau = Gamma
        return self._recovery_prove_ell(ell_t, d, C, Xt, Zt)


# ---------------------------------------------------------------------------
# Sanity check (small, fast round-trip -- run this before trusting the full
# benchmark sweep)
# ---------------------------------------------------------------------------

def _require(cond, msg):
    if not cond:
        raise AssertionError(msg)


def sanity_check(curve='BN254', n=5, k=1, L=8, seed=42):
    """Small end-to-end check of the construction. Run it under real Charm
    before trusting any benchmark: it exercises every algorithm
    through the definition's own objects (Gamma_t, Omega_t) and through the
    round-number interface, and confirms that tampered or malformed input is
    rejected cleanly."""
    pyrandom.seed(seed)
    scheme = CRVDA_AOE(curve)
    scheme.setup(n, k, L, sid=b'sanity-sid')
    scheme.build_bsgs()
    group = scheme.group

    xs = [pyrandom.randint(0, 2 ** L - 1) for _ in range(n)]
    t = 0
    reports = [scheme.report(i, t, xs[i - 1]) for i in range(1, n + 1)]
    for r in reports:
        _require(scheme.verify_rep(r), "a valid report failed VerifyRep")

    T, C, d = scheme.build(t, reports)
    _require(scheme.good_trans(t, T, C, d), "GoodTrans failed on an honest transcript")

    shares = {j: scheme.cert_share(j, t, T, C, d) for j in scheme.Q}
    Gamma = scheme.cert_combine_gamma(t, C, d, shares)
    _require(scheme.verify_gamma(Gamma), "VerifyCert failed on an honest certificate")

    Xt, Zt = scheme.aggr_dec_gamma(Gamma)
    _require(Xt == sum(xs), f"recovered sum {Xt} != true sum {sum(xs)}")
    pi_dec = scheme.dec_prove(Gamma, Xt, Zt)
    Omega = (Gamma, Xt, Zt, pi_dec)
    _require(scheme.verify_omega(Omega), "Verify(Omega_t) failed on an honest result")

    # the round-number interface (used by the benchmark harness) agrees
    tau = Gamma[3]
    _require(scheme.verify_cert(t, d, C, tau), "round-number VerifyCert disagrees")
    _require(scheme.aggr_dec(t, C, tau, d) == (Xt, Zt), "round-number AggrDec disagrees")
    proof = scheme.recovery_prove(t, d, C, Xt, Zt)
    _require(scheme.recovery_verify(t, d, C, Xt, Zt, proof), "recovery proof failed to verify")
    _require(scheme.verify(t, (d, C, tau), Xt, Zt, proof), "round-number Verify disagrees")

    # tampered and malformed input must be rejected, never raised
    _require(not scheme.verify_omega((Gamma, Xt + 1, Zt, pi_dec)), "a wrong X_t was accepted")
    r1 = reports[1]
    _require(not scheme.verify_rep((r1[0], r1[1], r1[2] * scheme.g1, r1[3], r1[4])),
             "a report with an altered ciphertext was accepted")
    for malformed in (None, (0,) + tuple(r1[1:]), tuple(r1[:3])):
        _require(scheme.verify_rep(malformed) is False, "a malformed report was not rejected cleanly")
    _require(scheme.verify_omega(None) is False, "a malformed Omega_t was not rejected cleanly")
    _require(random_nonzero(group) != group.init(ZR, 0), "random_nonzero returned zero")

    # an aggregator holding (s0, t0) fabricates a ciphertext with a genuine
    # recovery proof: the recovery check alone accepts it, Verify(Omega_t) must not
    Xf = min(500, n * (2 ** L - 1))
    ell_t = scheme.ell(t)
    Zf = (hash_to_g1(group, b'H1', ell_t) ** scheme.s0) * (hash_to_g1(group, b'H2', ell_t) ** scheme.t0)
    Cf = (scheme.g1 ** group.init(ZR, Xf)) * (Zf ** zneg(group, group.init(ZR, 1)))
    Gf = (ell_t, d, Cf, tau)
    pf = scheme.dec_prove(Gf, Xf, Zf)
    _require(scheme._recovery_verify_ell(ell_t, d, Cf, Xf, Zf, pf),
             "the recovery proof over a fabricated ciphertext should verify on its own")
    _require(not scheme.verify_omega((Gf, Xf, Zf, pf)),
             "Verify(Omega_t) accepted a fabricated ciphertext")

    print(f"sanity_check passed (n={n}, k={k}, L={L}, sum={Xt})")



# ---------------------------------------------------------------------------
# Real-valued dataset loading (fixed-point encoding)
# ---------------------------------------------------------------------------

def load_real_readings(path, decimal_places=3, sheet_name=0, column=0, has_header=True):
    import pandas as pd
    header_arg = 0 if has_header else None
    df = pd.read_excel(path, sheet_name=sheet_name, header=header_arg)
    raw = df.iloc[:, column].dropna().astype(float).tolist()
    scale = 10 ** decimal_places
    scaled = [int(round(v * scale)) for v in raw]
    if any(v < 0 for v in scaled):
        raise ValueError(
            "negative readings are not supported: the range proof only "
            "covers 0 <= x < 2^L"
        )
    if not scaled:
        raise ValueError(f"no numeric values found in column {column} of {path}")
    return scaled, scale


def get_dataset_values(dataset, n):
    """Return n plaintext values drawn from dataset, cycling with a
    printed warning if n exceeds the dataset size (matches the existing
    PPDA benchmarking convention for participant counts above the
    dataset size)."""
    if n <= len(dataset):
        return dataset[:n]
    print(f"WARNING: n={n} exceeds dataset size {len(dataset)}; cycling dataset")
    return [dataset[i % len(dataset)] for i in range(n)]


def required_L(max_value: int) -> int:
    """Smallest power-of-two bit length L with max_value <= 2^L - 1.
    Bulletproofs requires L itself (the vector length) to be a power of
    two for the recursive halving argument, so L can only ever be raised
    to the next power of two, not set to the exact bit length needed."""
    bits_needed = max(max_value.bit_length(), 1)
    L = 1
    while L < bits_needed:
        L *= 2
    return L


# ---------------------------------------------------------------------------
# Benchmark harness
# ---------------------------------------------------------------------------

# Practicality bound for a smart-grid deployment: a full round (every phase
# except the one-time Setup) must complete within a typical AMI reporting
# interval. 15 minutes is the interval this is checked against, per your
# requirement.
PRACTICAL_TIME_LIMIT_SECONDS = 15 * 60


def _quantile(sorted_vals, q):
    """Linear-interpolation quantile (numpy's default method)."""
    n = len(sorted_vals)
    if n == 1:
        return sorted_vals[0]
    pos = q * (n - 1)
    lo = int(math.floor(pos))
    hi = min(lo + 1, n - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def _stats(lst):
    """Summary of repeated timings (R34): mean, SAMPLE standard deviation
    (N-1 denominator; 0 for a single trial), median and quartiles (the
    interquartile range is q3 - q1), in the units of the input."""
    n = len(lst)
    mean = sum(lst) / n
    var = sum((v - mean) ** 2 for v in lst) / (n - 1) if n > 1 else 0.0
    srt = sorted(lst)
    return {'mean': mean, 'std': var ** 0.5, 'median': _quantile(srt, 0.5),
            'q1': _quantile(srt, 0.25), 'q3': _quantile(srt, 0.75), 'n': n}


def _charm_version():
    try:
        from importlib import metadata
    except ImportError:
        return 'unknown (importlib.metadata unavailable)'
    for name in ('charm-crypto-framework', 'charm-crypto', 'Charm-Crypto',
                 'charm_crypto_framework'):
        try:
            return f"{metadata.version(name)} (distribution '{name}')"
        except Exception:
            continue
    return ('NOT FOUND via importlib.metadata -- record it manually '
            '(e.g. if Charm was installed from source)')


def environment_info(curve, L, trials, warmup_rounds, seed, data_source, sweep):
    return {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S %Z'),
        'os': platform.platform(),
        'machine': platform.machine(),
        'processor': platform.processor() or 'n/a',
        'cpu_count': os.cpu_count(),
        'python': f"{platform.python_implementation()} {platform.python_version()}",
        'charm_crypto_version': _charm_version(),
        'pairing_backend': 'NOT auto-detected -- record it from your Charm build (default: PBC)',
        'curve': curve,
        'groups': 'Type-3 pairing via Charm PairingGroup: G1, G2, GT and Zp (prime order)',
        'L': L,
        'range_proof': ('single-value Bulletproof (Buenz et al., IEEE S&P 2018, Sec. 4.2); '
                        'vector generators hash-derived; g1 reused as the inner-product base'),
        'report_signature': 'Schnorr (R, z): one G1 element + one scalar',
        'bounded_dlog': ('baby-step giant-step over [0, n(2^L-1)]; the table is built once '
                         'after Setup, reported as bsgs_precompute, and excluded from the '
                         'per-round DC time (dc_recovery_total = aggrdec + recovery_prove)'),
        'certcombine_share_checks': ('k+1 checks, two SEPARATE pairings each '
                                     '(no multi-pairing / batch API)'),
        'sweep': sweep,
        'input_data': data_source,
        'trials_per_point': trials,
        'warmup': (f"{warmup_rounds} untimed full protocol round(s) on a small instance "
                   f"(n=8, k=1, same L and curve), once before the sweep"),
        'seed': seed,
        'statistics': ('CSV gives mean, sample standard deviation (N-1), median, quartiles '
                       'and IQR per point; choose one summary for the paper and state it'),
        'timer': 'time.perf_counter() (wall clock), single process, no network transfer',
        'timing_includes': ('hash-to-group, Fiat-Shamir and digest hashing, and the message '
                            'serialization performed inside each timed method'),
        'timing_excludes': ('Setup (reported separately, not part of the round totals), '
                            'bounded-DLog precomputation (reported separately), test-input '
                            'generation, printing and CSV output'),
        'measurement_policy': ('each (n, k%) point is measured independently with a fresh '
                               'scheme instance per trial; nothing is extrapolated, except '
                               'the derived columns certshare_total_Q and cert_total_work '
                               '= (k+1) x one measured certifier; shares of members 2..k+1 '
                               'are computed directly (Hcm ** zj) by the harness'),
    }


def write_environment(info, path):
    with open(path, 'w') as f:
        for key, val in info.items():
            f.write(f"{key}: {val}\n")


def _warmup(curve, L, rounds, n_warm=8, k_warm=1):
    """Untimed full protocol rounds on a small instance, so that first-call
    effects (lazy imports, allocator and cache warm-up, first table builds)
    do not land in the first measured trial. Uses its own RNG so the seeded
    measurement inputs are unaffected."""
    rng = pyrandom.Random(12345)
    for w in range(rounds):
        scheme = CRVDA_AOE(curve)
        scheme.setup(n_warm, k_warm, L, sid=f"warmup-{w}".encode())
        scheme.build_bsgs()
        xs = [rng.randint(0, 2 ** L - 1) for _ in range(n_warm)]
        reports = [scheme.report(i, w, xs[i - 1]) for i in range(1, n_warm + 1)]
        T, C, d = scheme.build(w, reports)
        shares = {j: scheme.cert_share(j, w, T, C, d) for j in scheme.Q}
        tau = scheme.cert_combine(w, C, d, shares)
        Xt, Zt = scheme.aggr_dec(w, C, tau, d)
        proof = scheme.recovery_prove(w, d, C, Xt, Zt)
        assert scheme.verify(w, (d, C, tau), Xt, Zt, proof)


def flatness_report(rows, phase, note=''):
    """how much does `phase` vary with n? Prints each n's mean (averaged
    over the k% values), the spread (max - min) as a percentage of the
    overall mean, and the drift across the n range implied by a least-squares
    line, also as a percentage of the overall mean. Numbers only -- no
    pass/fail threshold is imposed."""
    per_n = {}
    for r in rows:
        if r['phase'] == phase:
            per_n.setdefault(r['n'], []).append(r['mean_ms'])
    if len(per_n) < 2:
        return
    ns = sorted(per_n)
    means = [sum(per_n[n]) / len(per_n[n]) for n in ns]
    overall = sum(means) / len(means)
    spread = 100 * (max(means) - min(means)) / overall if overall else float('nan')
    nbar = sum(ns) / len(ns)
    sxx = sum((n - nbar) ** 2 for n in ns)
    slope = (sum((n - nbar) * (m - overall) for n, m in zip(ns, means)) / sxx) if sxx else 0.0
    drift = 100 * slope * (ns[-1] - ns[0]) / overall if overall else float('nan')
    series = ", ".join(f"n={n}: {m:.3f}" for n, m in zip(ns, means))
    print(f"  {phase}{note}: spread {spread:.1f}% of mean, fitted drift over the "
          f"n range {drift:+.1f}% of mean  [{series}] ms")


def run_benchmarks(Ns, trials=10, k_percents=(0, 10, 20, 30), L=16, curve='BN254',
                    csv_path='crvda_aoe_benchmarks.csv', seed=1234,
                    real_data_path=None, decimal_places=3, real_data_column=0,
                    real_data_has_header=True,
                    practical_limit_seconds=PRACTICAL_TIME_LIMIT_SECONDS,
                    warmup_rounds=1, env_path='crvda_aoe_benchmark_env.txt'):

    pyrandom.seed(seed)
    rows = []

    all_within_limit = True

    dataset = None
    scale = 1
    if real_data_path is not None:
        dataset, scale = load_real_readings(real_data_path, decimal_places,
                                             column=real_data_column,
                                             has_header=real_data_has_header)
        needed_L = required_L(max(dataset))
        if needed_L > L:
            print(f"Raising L from {L} to {needed_L} to cover the dataset's "
                  f"largest scaled value ({max(dataset)}) at "
                  f"{decimal_places} decimal places.")
            L = needed_L
        print(f"Loaded {len(dataset)} real-valued readings from "
              f"{real_data_path} (scale=10^{decimal_places}, "
              f"max scaled value={max(dataset)}, L={L}).")

    data_source = (f"real dataset {real_data_path} (fixed-point scale 10^{decimal_places})"
                   if dataset is not None
                   else "synthetic uniform random readings in [0, 2^L)")
    if env_path:      # the environment record is printed and written only when a path is given
        env = environment_info(curve, L, trials, warmup_rounds, seed, data_source,
                               f"n in {list(Ns)}, k% in {list(k_percents)}")
        print("Benchmark environment (R34):")
        for key_, val_ in env.items():
            print(f"  {key_}: {val_}")
        write_environment(env, env_path)
        print(f"Wrote {env_path}")
    if warmup_rounds > 0:
        print(f"Warm-up: {warmup_rounds} untimed round(s) on n=8, k=1, L={L} ...")
        _warmup(curve, L, warmup_rounds)

    for n in Ns:
        for k_pct in k_percents:
            k = math.ceil((k_pct / 100) * n)
            if k > n - 2:          # the adversary bound of Sec. VI-B: k <= n - 2
                k = n - 2
            print(f"\n=== n={n}, k={k} ({k_pct}%), |Q|={k + 1}, L={L} ===")

            t_setup, t_report, t_verifyrep, t_allreports = [], [], [], []
            t_build, t_certshare, t_certcombine = [], [], []
            t_aggrdec, t_recprove = [], []
            t_bsgs_pre = []
            t_aggrdec_certcheck, t_aggrdec_mask, t_aggrdec_dlog = [], [], []
            t_dc_total = []
            t_certcombine_checks, t_certcombine_mult = [], []
            t_certshare_totalQ, t_cert_total_work = [], []
            t_final_cert, t_final_recovery, t_final_verify = [], [], []
            t_total_distributed, t_total_sequential = [], []
            t_report_encrypt, t_report_proofgen, t_report_sign = [], [], []
            t_verify_sig, t_verify_link, t_verify_range = [], [], []
            t_goodtrans_reportcheck, t_goodtrans_aggcheck, t_goodtrans_digest = [], [], []
            t_certshare_bls = []

            for trial in range(trials):
                scheme = CRVDA_AOE(curve)

                t0 = time.perf_counter()
                scheme.setup(n, k, L, sid=f"sid-{n}-{k_pct}-{trial}".encode())
                t_setup.append(time.perf_counter() - t0)

                # Bounded-DLog table: built once after Setup, reported
                # separately, excluded from the per-round DC time (R31).
                t0 = time.perf_counter()
                scheme.build_bsgs()
                t_bsgs_pre.append(time.perf_counter() - t0)
                if trial == 0:
                    bsgs_bound, bsgs_entries = scheme.bsgs_info()
                    print(f"  BSGS (R31): search bound n(2^L-1) = {bsgs_bound}, "
                          f"baby-step table entries = {bsgs_entries} "
                          f"(built once after Setup; excluded from per-round DC time)")

                if dataset is not None:
                    xs = get_dataset_values(dataset, n)
                else:
                    xs = [pyrandom.randint(0, 2 ** L - 1) for _ in range(n)]
                t = trial

                R1, r1_timing = scheme.report(1, t, xs[0], return_timing=True)
                t_report_encrypt.append(r1_timing['encrypt'])
                t_report_proofgen.append(r1_timing['proofgen'])
                t_report_sign.append(r1_timing['sign'])
                # report_single total, derived as the sum of the three
                # sub-phases just measured (not a separate outer-wrapper
                # timing) -- see the report()/verify_rep() docstrings.
                t_report.append(r1_timing['encrypt'] + r1_timing['proofgen']
                                 + r1_timing['sign'])

                ok, v1_timing = scheme.verify_rep(R1, return_timing=True)
                t_verify_sig.append(v1_timing['sig'])
                t_verify_link.append(v1_timing['link'])
                t_verify_range.append(v1_timing['range'])
                t_verifyrep.append(v1_timing['sig'] + v1_timing['link']
                                    + v1_timing['range'])
                assert ok

                t0 = time.perf_counter()
                reports = [R1] + [scheme.report(i, t, xs[i - 1]) for i in range(2, n + 1)]
                t_allreports.append((time.perf_counter() - t0) + t_report[-1])

                t0 = time.perf_counter()
                T, C, d = scheme.build(t, reports)
                t_build.append(time.perf_counter() - t0)

                shares = {}
                shares[scheme.Q[0]], gt_timing = scheme.cert_share(
                    scheme.Q[0], t, T, C, d, return_timing=True)
                t_goodtrans_reportcheck.append(gt_timing['reportcheck'])
                t_goodtrans_aggcheck.append(gt_timing['aggcheck'])
                t_goodtrans_digest.append(gt_timing['digest'])
                t_certshare_bls.append(gt_timing['bls'])
                # certshare_single total, derived as the sum of the four
                # sub-phases just measured -- same convention as
                # report_single/verifyrep_single above.
                t_certshare.append(gt_timing['reportcheck'] + gt_timing['aggcheck']
                                    + gt_timing['digest'] + gt_timing['bls'])
              
                Hcm = scheme._cert_message_hash(t, C, d)
                for j in scheme.Q[1:]:
                    shares[j] = Hcm ** scheme.z[j]

                # (4) CertCombine: the k+1 share checks + multiplication
                tau, cc_timing = scheme.cert_combine(t, C, d, shares,
                                                     return_timing=True)
                t_certcombine_checks.append(cc_timing['sharechecks'])
                t_certcombine_mult.append(cc_timing['multiply'])
                t_certcombine.append(cc_timing['sharechecks'] + cc_timing['multiply'])

                # Certification totals. Single-certifier latency is
                # certshare_single; total work across the k+1 certifiers is
                # DERIVED -- all members run the identical GoodTrans on the
                # identical transcript, so (k+1) x one measured member.
                t_certshare_totalQ.append((k + 1) * t_certshare[-1])
                t_cert_total_work.append(t_certshare_totalQ[-1] + t_certcombine[-1])

                # DC: AggrDec (VerifyCert gate + mask + bounded dlog),
                # then the recovery proof
                Xt, Zt, ad_timing = scheme.aggr_dec(t, C, tau, d, return_timing=True)
                assert Xt == sum(xs)
                t_aggrdec_certcheck.append(ad_timing['certcheck'])
                t_aggrdec_mask.append(ad_timing['mask'])
                t_aggrdec_dlog.append(ad_timing['dlog'])
                t_aggrdec.append(ad_timing['certcheck'] + ad_timing['mask']
                                  + ad_timing['dlog'])
                if dataset is not None and trial == 0:
                    print(f"  (n={n}, k%={k_pct}, trial 0: recovered scaled "
                          f"sum={Xt}, real-valued sum="
                          f"{Xt / scale:.{decimal_places}f})")

                t0 = time.perf_counter()
                proof = scheme.recovery_prove(t, d, C, Xt, Zt)
                t_recprove.append(time.perf_counter() - t0)
                t_dc_total.append(t_aggrdec[-1] + t_recprove[-1])

                # final public verification: Verify(Omega_t) -- the
                # constant-size path (VerifyCert + recovery proof + range check)
                okv, fv_timing = scheme.verify(t, (d, C, tau), Xt, Zt, proof,
                                               return_timing=True)
                assert okv
                t_final_cert.append(fv_timing['cert'])
                t_final_recovery.append(fv_timing['recovery'])
                t_final_verify.append(fv_timing['cert'] + fv_timing['recovery'])

                # Per-trial totals, Setup excluded; the six stages are disjoint, so nothing
                # is counted twice.
                total_distributed = (t_report[-1] + t_build[-1] + t_certshare[-1]
                                      + t_certcombine[-1] + t_dc_total[-1]
                                      + t_final_verify[-1])
                total_sequential = (t_allreports[-1] + t_build[-1]
                                     + t_certshare_totalQ[-1] + t_certcombine[-1]
                                     + t_dc_total[-1] + t_final_verify[-1])
                t_total_distributed.append(total_distributed)
                t_total_sequential.append(total_sequential)

                if total_distributed > practical_limit_seconds:
                    all_within_limit = False
                    print(f"  WARNING: n={n}, k%={k_pct}, trial={trial}: "
                          f"total_distributed={total_distributed:.3f}s exceeds "
                          f"the {practical_limit_seconds}s practicality limit")
                if total_sequential > practical_limit_seconds:
                    print(f"  NOTE: n={n}, k%={k_pct}, trial={trial}: "
                          f"total_sequential={total_sequential:.3f}s (all work on "
                          f"one machine) exceeds {practical_limit_seconds}s; "
                          f"informational only")

            phase_stats = {
                'setup': _stats(t_setup),
                'bsgs_precompute': _stats(t_bsgs_pre),
                # (1) per-meter report generation
                'report_single': _stats(t_report),
                'report_encrypt': _stats(t_report_encrypt),
                'report_proofgen': _stats(t_report_proofgen),
                'report_sign': _stats(t_report_sign),
                'all_reports_gen': _stats(t_allreports),
                # per-report verification (what each certifier repeats n times)
                'verifyrep_single': _stats(t_verifyrep),
                'verifyrep_sig': _stats(t_verify_sig),
                'verifyrep_link': _stats(t_verify_link),
                'verifyrep_range': _stats(t_verify_range),
                # (2) AG transcript build
                'build': _stats(t_build),
                # (3) one quorum member's GoodTrans + BLS share, and total over k+1
                'certshare_single': _stats(t_certshare),
                'goodtrans_reportcheck': _stats(t_goodtrans_reportcheck),
                'goodtrans_aggcheck': _stats(t_goodtrans_aggcheck),
                'goodtrans_digest': _stats(t_goodtrans_digest),
                'certshare_bls': _stats(t_certshare_bls),
                'certshare_total_Q': _stats(t_certshare_totalQ),
                # (4) CertCombine
                'certcombine': _stats(t_certcombine),
                'certcombine_sharechecks': _stats(t_certcombine_checks),
                'certcombine_multiply': _stats(t_certcombine_mult),
                'cert_total_work': _stats(t_cert_total_work),
                # (5) DC recovery + recovery proof
                'aggrdec': _stats(t_aggrdec),
                'aggrdec_certcheck': _stats(t_aggrdec_certcheck),
                'aggrdec_mask': _stats(t_aggrdec_mask),
                'aggrdec_dlog': _stats(t_aggrdec_dlog),
                'recovery_prove': _stats(t_recprove),
                'dc_recovery_total': _stats(t_dc_total),
                # (6) final public verification (constant-size path)
                'final_verify': _stats(t_final_verify),
                'final_verify_cert': _stats(t_final_cert),
                'final_verify_recovery': _stats(t_final_recovery),
                'total_distributed': _stats(t_total_distributed),
                'total_sequential': _stats(t_total_sequential),
            }
            for phase, st in phase_stats.items():
                iqr = st['q3'] - st['q1']
                print(f"  {phase:24s} mean={st['mean'] * 1000:10.3f} ms  "
                      f"std={st['std'] * 1000:9.3f}  median={st['median'] * 1000:10.3f}  "
                      f"IQR={iqr * 1000:9.3f}")
                rows.append({'n': n, 'k_pct': k_pct, 'k': k, 'phase': phase,
                             'mean_ms': st['mean'] * 1000, 'std_ms': st['std'] * 1000,
                             'median_ms': st['median'] * 1000, 'q1_ms': st['q1'] * 1000,
                             'q3_ms': st['q3'] * 1000, 'iqr_ms': iqr * 1000,
                             'trials': st['n']})

            worst_distributed = max(t_total_distributed)
            worst_sequential = max(t_total_sequential)
            print(f"  --> practicality check (limit={practical_limit_seconds}s): "
                  f"worst-case total_distributed={worst_distributed:.3f}s, "
                  f"worst-case total_sequential={worst_sequential:.3f}s")

    if csv_path:
        with open(csv_path, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['n', 'k_pct', 'k', 'phase', 'mean_ms',
                                              'std_ms', 'median_ms', 'q1_ms', 'q3_ms',
                                              'iqr_ms', 'trials'])
            w.writeheader()
            w.writerows(rows)
        print(f"\nWrote {csv_path}")

    if len(set(Ns)) >= 2:
        print("\nFlatness checks across n (R30; numbers only):")
        flatness_report(rows, 'final_verify', '  [claim: constant, no per-report work]')
        flatness_report(rows, 'report_single', '  [claim: meter-local, independent of n]')

    if all_within_limit:
        print(f"\nPRACTICALITY CHECK PASSED: every (n, k%, trial) combination "
              f"completed within {practical_limit_seconds}s ("
              f"{practical_limit_seconds / 60:.0f} minutes), excluding Setup, "
              f"under the total_distributed definition (parallel meters and "
              f"certifiers). total_sequential (all work on one machine) is "
              f"reported separately and is informational only.")
    else:
        print(f"\nPRACTICALITY CHECK FAILED: at least one (n, k%, trial) "
              f"combination exceeded {practical_limit_seconds}s under "
              f"total_distributed -- see the WARNING lines above for which ones.")

    return rows, all_within_limit


if __name__ == '__main__':
    sanity_check()

    Ns = [50, 100, 250, 500, 750, 1000]
    run_benchmarks(Ns, trials=10, k_percents=(0, 10, 20, 30), L=16,
                    curve='BN254', csv_path='crvda_aoe_benchmarks.csv')