"""
crvda_wire.py -- byte-exact wire encoding of the CRVDA-AOE messages
====================================================================

"Record raw serialized byte lengths for R_i, Gamma_t, Omega_t, the roster, and the full transcript. Explain the encoding of
i and the round label." This module turns every protocol message into the
exact bytes that go on the wire and back, so the sizes in the paper are the
lengths of real encodings that a receiver can decode and verify -- not counts
of group elements.

Encoding (all integers big-endian, no type tags, no length prefixes: every
message has a fixed layout determined by the public parameters n, k, L)

  G1 element   32 B   compressed: x-coordinate, the y-sign bit stored in the
                      unused top bit of x (BN254: x < p < 2^254)
  G2 element   64 B   compressed: x in F_p^2, y-sign bit in the top bit
  Z_p scalar   32 B   canonical (decoder rejects values >= group order)
  i, j          2 B   uint16 meter / quorum-member identity (n <= 65,535)
  t             4 B   uint32 round number. The round label is NOT sent:
                      every receiver recomputes ell_t = ROUND||sid||t||rid
                      from the public sid and rid, and all signatures,
                      challenges and certificates are computed over the full
                      ell_t exactly as before. A report replayed under another
                      t, sid or roster therefore fails its signature check.
  d            32 B   transcript digest H_D (SHA-256)
  X_t        4 or 8 B uint32 when n(2^L - 1) < 2^32 (all L <= 16 settings up to
                      n = 65,537), otherwise uint64 (e.g. L = 32)
"""

import base64

from charm.toolbox.pairinggroup import ZR, G1, G2

import crvda_aoe_v2 as C

ZR_BYTES = 32
ID_BYTES, ROUND_BYTES, DIGEST_BYTES = 2, 4, 32


def x_bytes(n, L):
    """Width of the X_t field: 4 bytes when the bound n(2^L - 1) fits a
    uint32, otherwise 8. Fixed by the public parameters (n, L)."""
    return 4 if n * (2 ** L - 1) < 2 ** 32 else 8
_COMPACT = {G1: 32, G2: 64}


class WireError(ValueError):
    """A message could not be decoded (wrong length, invalid or non-canonical
    element, inconsistent public parameters). Receivers treat it as reject."""


def _u(v, nbytes, what):
    if not (0 <= v < 2 ** (8 * nbytes)):
        raise WireError(f"{what} = {v} does not fit in {nbytes} bytes")
    return v.to_bytes(nbytes, 'big')


class _Reader:
    def __init__(self, wire, data):
        self.w, self.b, self.pos = wire, bytes(data), 0

    def take(self, n):
        if self.pos + n > len(self.b):
            raise WireError("message is truncated")
        out = self.b[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return int.from_bytes(self.take(2), 'big')

    def u32(self):
        return int.from_bytes(self.take(4), 'big')

    def g1(self):
        return self.w.dec_point(G1, self.take(self.w.size[G1]))

    def g2(self):
        return self.w.dec_point(G2, self.take(self.w.size[G2]))

    def zr(self):
        return self.w.dec_zr(self.take(ZR_BYTES))

    def end(self):
        if self.pos != len(self.b):
            raise WireError(f"{len(self.b) - self.pos} unexpected trailing bytes")


class Wire:
    def __init__(self, group, samples=16):
        self.group = group
        self.p = int(group.order())
        self.layout, self.prefix, self.size = {}, {}, {}
        for gtype in (G1, G2):
            self._detect(gtype, samples)
        self.compact = all(self.layout[g] != 'raw' for g in (G1, G2))

    # ---- element encodings --------------------------------------------------

    def _raw(self, e):
        s = self.group.serialize(e)
        prefix, sep, b64 = s.partition(b':')
        if not sep:
            raise WireError("unrecognised Charm serialization")
        return prefix, base64.b64decode(b64)

    def _detect(self, gtype, samples):
        xlen = _COMPACT[gtype]
        elems = [self.group.random(gtype) for _ in range(samples)]
        raws = [self._raw(e) for e in elems]
        prefixes = {p for p, _ in raws}
        lens = {len(r) for _, r in raws}
        if len(prefixes) != 1 or len(lens) != 1:
            raise WireError("Charm serialization of this group is not fixed-length")
        self.prefix[gtype] = prefixes.pop()
        rlen = lens.pop()
        rs = [r for _, r in raws]
        layout = 'raw'
        if rlen == xlen + 1 and all(r[-1] in (0, 1) and r[0] < 0x80 for r in rs):
            layout = 'flag_last'
        elif rlen == xlen + 1 and all(r[0] in (0, 1) and r[1] < 0x80 for r in rs):
            layout = 'flag_first'
        self.layout[gtype] = layout
        self.size[gtype] = xlen if layout != 'raw' else rlen
        if layout != 'raw':
            try:
                ok = all(self.dec_point(gtype, self.enc_point(gtype, e)) == e for e in elems)
            except Exception:
                ok = False
            if not ok:
                self.layout[gtype], self.size[gtype] = 'raw', rlen

    def enc_point(self, gtype, e):
        _, raw = self._raw(e)
        lay = self.layout[gtype]
        if lay == 'raw':
            return raw
        if lay == 'flag_last':
            x, flag = bytearray(raw[:-1]), raw[-1]
        else:
            x, flag = bytearray(raw[1:]), raw[0]
        if x[0] & 0x80 or flag not in (0, 1):
            raise WireError("point encoding has no spare bit for the sign")
        x[0] |= flag << 7
        return bytes(x)

    def dec_point(self, gtype, b):
        b = bytes(b)
        if len(b) != self.size[gtype]:
            raise WireError("group element has the wrong length")
        lay = self.layout[gtype]
        if lay == 'raw':
            raw = b
        else:
            x = bytearray(b)
            flag = x[0] >> 7
            x[0] &= 0x7F
            raw = bytes(x) + bytes([flag]) if lay == 'flag_last' else bytes([flag]) + bytes(x)
        try:
            e = self.group.deserialize(self.prefix[gtype] + b':' + base64.b64encode(raw))
        except Exception as ex:
            raise WireError(f"invalid group element ({ex})")
        if e is None:
            raise WireError("invalid group element")
        try:
            canonical = self.enc_point(gtype, e) == b
        except Exception:
            canonical = False
        if not canonical:
            raise WireError("invalid or non-canonical group element")
        return e

    def enc_zr(self, e):
        return int(e).to_bytes(ZR_BYTES, 'big')

    def dec_zr(self, b):
        v = int.from_bytes(b, 'big')
        if v >= self.p:
            raise WireError("non-canonical scalar (not reduced modulo the group order)")
        return self.group.init(ZR, v)

    # ---- sizes ----------------------------------------------------------------

    def report_len(self, L):
        r = L.bit_length() - 1
        return ID_BYTES + ROUND_BYTES + (2 * r + 10) * self.size[G1] + 11 * ZR_BYTES

    def dist_len(self, n, L):
        return ROUND_BYTES + DIGEST_BYTES + self.size[G1] + n * self.report_len(L)

    def gamma_len(self):
        return ROUND_BYTES + DIGEST_BYTES + 2 * self.size[G1]

    def omega_len(self, sch):
        return self.gamma_len() + x_bytes(sch.n, sch.L) + 4 * self.size[G1] + 2 * ZR_BYTES

    # ---- R_i ------------------------------------------------------------------

    def enc_report(self, sch, R, t):
        i, ell_t, Ci, (V, plink, pr), (sR, sz) = R
        if ell_t != sch.ell(t):
            raise WireError("report label does not match round t")
        rounds = sch.L.bit_length() - 1
        ipa = pr['ipa']
        if len(ipa['L']) != rounds or len(ipa['R']) != rounds:
            raise WireError("range proof has the wrong number of rounds")
        g, z = (lambda e: self.enc_point(G1, e)), self.enc_zr
        out = [_u(i, ID_BYTES, 'i'), _u(t, ROUND_BYTES, 't'), g(Ci), g(V)]
        out += [g(e) for e in plink[:3]] + [z(e) for e in plink[3:]]
        out += [g(pr[k]) for k in ('A', 'S', 'T1', 'T2')]
        out += [z(pr[k]) for k in ('tau_x', 'mu', 't')]
        out += [g(e) for e in ipa['L']] + [g(e) for e in ipa['R']]
        out += [z(ipa['a']), z(ipa['b']), g(sR), z(sz)]
        return b''.join(out)

    def _read_report(self, rd, sch):
        rounds = sch.L.bit_length() - 1
        i, t = rd.u16(), rd.u32()
        Ci, V = rd.g1(), rd.g1()
        plink = (rd.g1(), rd.g1(), rd.g1(), rd.zr(), rd.zr(), rd.zr(), rd.zr(), rd.zr())
        A, S, T1, T2 = rd.g1(), rd.g1(), rd.g1(), rd.g1()
        tau_x, mu, tt = rd.zr(), rd.zr(), rd.zr()
        Ls = [rd.g1() for _ in range(rounds)]
        Rs = [rd.g1() for _ in range(rounds)]
        a, b = rd.zr(), rd.zr()
        sig = (rd.g1(), rd.zr())
        pr = {'A': A, 'S': S, 'T1': T1, 'T2': T2, 'tau_x': tau_x, 'mu': mu, 't': tt,
              'ipa': {'L': Ls, 'R': Rs, 'a': a, 'b': b}}
        return (i, sch.ell(t), Ci, (V, plink, pr), sig), t

    def dec_report(self, sch, data):
        if len(data) != self.report_len(sch.L):
            raise WireError("report has the wrong length")
        rd = _Reader(self, data)
        R, t = self._read_report(rd, sch)
        rd.end()
        return R, t

    # ---- AG -> quorum member: (t, d, C_t, T) -----------------------------------

    def enc_dist(self, sch, t, T, Ct, d):
        if len(d) != DIGEST_BYTES:
            raise WireError("digest has the wrong length")
        return b''.join([_u(t, ROUND_BYTES, 't'), d, self.enc_point(G1, Ct)]
                        + [self.enc_report(sch, R, t) for R in T])

    def dec_dist(self, sch, data):
        if len(data) != self.dist_len(sch.n, sch.L):
            raise WireError("transcript message has the wrong length for n reports")
        rd = _Reader(self, data)
        t, d, Ct = rd.u32(), rd.take(DIGEST_BYTES), rd.g1()
        T = []
        for _ in range(sch.n):
            R, tr = self._read_report(rd, sch)
            if tr != t:
                raise WireError("a report in the transcript carries another round")
            T.append(R)
        rd.end()
        return t, T, Ct, d

    # ---- theta_j ------------------------------------------------------------------

    def enc_share(self, theta):
        return self.enc_point(G1, theta)

    def dec_share(self, data):
        return self.dec_point(G1, data)

    # ---- Gamma_t = (ell_t, d, C_t, tau), sent as (t, d, C_t, tau) -----------------

    def enc_gamma(self, sch, t, Gamma):
        ell_t, d, Ct, tau = Gamma
        if ell_t != sch.ell(t):
            raise WireError("Gamma label does not match round t")
        return b''.join([_u(t, ROUND_BYTES, 't'), d, self.enc_point(G1, Ct), self.enc_point(G1, tau)])

    def _read_gamma(self, rd, sch):
        t, d, Ct, tau = rd.u32(), rd.take(DIGEST_BYTES), rd.g1(), rd.g1()
        return (sch.ell(t), d, Ct, tau), t

    def dec_gamma(self, sch, data):
        if len(data) != self.gamma_len():
            raise WireError("Gamma has the wrong length")
        rd = _Reader(self, data)
        G, t = self._read_gamma(rd, sch)
        rd.end()
        return G, t

    # ---- Omega_t = (Gamma_t, X_t, Z_t, pi_dec) --------------------------------------

    def enc_omega(self, sch, t, Omega):
        Gamma, Xt, Zt, (D1, D2, D3, ys, yt) = Omega
        return b''.join([self.enc_gamma(sch, t, Gamma), _u(Xt, x_bytes(sch.n, sch.L), 'X_t'),
                         self.enc_point(G1, Zt), self.enc_point(G1, D1), self.enc_point(G1, D2),
                         self.enc_point(G1, D3), self.enc_zr(ys), self.enc_zr(yt)])

    def dec_omega(self, sch, data):
        if len(data) != self.omega_len(sch):
            raise WireError("Omega has the wrong length")
        rd = _Reader(self, data)
        Gamma, t = self._read_gamma(rd, sch)
        Xt = int.from_bytes(rd.take(x_bytes(sch.n, sch.L)), 'big')
        Zt = rd.g1()
        pi = (rd.g1(), rd.g1(), rd.g1(), rd.zr(), rd.zr())
        rd.end()
        return (Gamma, Xt, Zt, pi), t

    # ---- public parameters and roster -----------------------------------------------

    def enc_public(self, sch):
        if len(sch.sid) > 255:
            raise WireError("sid longer than 255 bytes")
        g1e, g2e = (lambda e: self.enc_point(G1, e)), (lambda e: self.enc_point(G2, e))
        out = [_u(sch.n, ID_BYTES, 'n'), _u(sch.k, ID_BYTES, 'k'), _u(sch.L, 1, 'L'),
               bytes([len(sch.sid)]), sch.sid, sch.rid,
               g1e(sch.g1), g2e(sch.g2), g1e(sch.u), g1e(sch.h),
               g1e(sch.S0), g1e(sch.T0), g2e(sch.WQ)]
        for i in range(1, sch.n + 1):
            out += [_u(i, ID_BYTES, 'i'), g1e(sch.rvk[i]), g1e(sch.K[i])]
        for j in sch.Q:
            out += [_u(j, ID_BYTES, 'j'), g2e(sch.W[j])]
        return b''.join(out)

    def dec_public(self, data):
        """Build a party (a CRVDA_AOE object holding ONLY public data) from the
        encoded public parameters. Secrets are added with add_secret()."""
        rd = _Reader(self, data)
        group = self.group
        n, k, L = rd.u16(), rd.u16(), rd.u8()
        sid = rd.take(rd.u8())
        rid = rd.take(DIGEST_BYTES)
        if rid != C.hd_digest(group, b'ROSTER', *range(1, n + 1)):
            raise WireError("rid does not match the roster 1..n")
        if not (0 <= k <= n - 2) or not (L > 0 and (L & (L - 1)) == 0):
            raise WireError("invalid (n, k, L)")
        g1, g2, u, h = rd.g1(), rd.g2(), rd.g1(), rd.g1()
        S0, T0, WQ = rd.g1(), rd.g1(), rd.g2()
        rvk, K = {}, {}
        for i in range(1, n + 1):
            if rd.u16() != i:
                raise WireError("roster identities out of order")
            rvk[i], K[i] = rd.g1(), rd.g1()
        Q, W = list(range(1, k + 2)), {}
        for j in Q:
            if rd.u16() != j:
                raise WireError("quorum identities out of order")
            W[j] = rd.g2()
        rd.end()
        prod = W[Q[0]]
        for j in Q[1:]:
            prod = prod * W[j]
        if prod != WQ:
            raise WireError("W_Q is not the product of the quorum keys")

        sch = C.CRVDA_AOE.__new__(C.CRVDA_AOE)
        sch.group = group
        sch.n, sch.k, sch.L, sch.sid, sch.rid = n, k, L, sid, rid
        sch.g1, sch.g2, sch.u, sch.h, sch.S0, sch.T0 = g1, g2, u, h, S0, T0
        sch.rvk, sch.K, sch.Q, sch.W, sch.WQ = rvk, K, Q, W, WQ
        # transparent generators: re-derived by hashing, never transmitted
        sch.hx = C.hash_to_g1(group, b'RANGE-GEN')
        sch.g_vec = [C.hash_to_g1(group, b'BP-G', idx) for idx in range(L)]
        sch.h_vec = [C.hash_to_g1(group, b'BP-H', idx) for idx in range(L)]
        sch.si, sch.ti, sch.rho, sch.rsk, sch.z = {}, {}, {}, {}, {}
        sch.s0 = sch.t0 = None
        sch._report_cache, sch._bsgs = {}, None
        return sch

    # ---- party secrets (delivered once by the dealer over a private channel) -------

    def enc_meter_secret(self, sch, i):
        return b''.join([b'\x01', _u(i, ID_BYTES, 'i'), self.enc_zr(sch.si[i]), self.enc_zr(sch.ti[i]),
                         self.enc_zr(sch.rho[i]), self.enc_zr(sch.rsk[i])])

    def enc_cert_secret(self, sch, j):
        return b''.join([b'\x02', _u(j, ID_BYTES, 'j'), self.enc_zr(sch.z[j])])

    def enc_dc_secret(self, sch):
        return b''.join([b'\x03', self.enc_zr(sch.s0), self.enc_zr(sch.t0)])

    def add_secret(self, sch, data):
        rd = _Reader(self, data)
        tag = rd.u8()
        if tag == 1:
            i = rd.u16()
            sch.si[i], sch.ti[i], sch.rho[i], sch.rsk[i] = rd.zr(), rd.zr(), rd.zr(), rd.zr()
        elif tag == 2:
            j = rd.u16()
            if j not in sch.Q:
                raise WireError("certification key for a non-quorum identity")
            sch.z[j] = rd.zr()
            if sch.g2 ** sch.z[j] != sch.W[j]:
                raise WireError("certification key does not match W_j")
        elif tag == 3:
            sch.s0, sch.t0 = rd.zr(), rd.zr()
            if sch.g1 ** sch.s0 != sch.S0 or sch.g1 ** sch.t0 != sch.T0:
                raise WireError("decryption key does not match S0, T0")
        else:
            raise WireError("unknown secret tag")
        rd.end()
        return sch