"""
test_hashing.py -- small checks of the version 2.0 hashing changes in crvda_aoe.py
(Fiat-Shamir rejection sampling, unambiguous hash-input encoding, zero-byte-safe
hash-to-group). Runs in a few seconds:   python3 test_hashing.py
"""
import hashlib

from charm.toolbox.pairinggroup import ZR

import crvda_aoe_v2 as C

FAILS = []


def check(cond, msg):
    print(("  PASS: " if cond else "  FAIL: ") + msg)
    if not cond:
        FAILS.append(msg)


def main():
    sch = C.CRVDA_AOE('BN254')
    sch.setup(5, 1, 16, sid=b'hash-test')
    G = sch.group
    p = int(G.order())
    L0 = ((1 << 256) // p) * p

    print("Version:", C.__version__, "| benchmarked version:", C.BENCHMARKED_VERSION)

    # --- 1. Fiat-Shamir challenge: deterministic, in Z_p, rejection path works
    c1 = C.fs_challenge(G, b'TAG', 1, sch.g1)
    c2 = C.fs_challenge(G, b'TAG', 1, sch.g1)
    check(c1 == c2, "H_FS is deterministic")
    check(C.fs_challenge(G, b'TAG', 2, sch.g1) != c1, "H_FS depends on its input")
    check(0 <= int(c1) < p, "H_FS output lies in Z_p")

    real_sha = hashlib.sha256
    calls = []

    class Forced:
        """Returns a digest >= L0 on the first call, so the first draw must be rejected."""
        def __init__(self, data):
            self.data = data
            calls.append(data)

        def digest(self):
            if len(calls) == 1:
                return (L0 + 5).to_bytes(32, 'big')
            return real_sha(self.data).digest()

    C.hashlib.sha256 = Forced
    try:
        c3 = C.fs_challenge(G, b'TAG', 1, sch.g1)
    finally:
        C.hashlib.sha256 = real_sha
    check(len(calls) == 2, "a draw >= floor(2^256/p)*p is rejected and the counter advances")
    check(calls[0] != calls[1],
          "the second draw hashes a different counter value")
    expected = int.from_bytes(real_sha(calls[1]).digest(), 'big') % p
    check(int(c3) == expected, "the accepted draw is output reduced mod p")

    # --- 2. Unambiguous encoding
    pairs = [((b'a|', b'b'), (b'a', b'|b')),
             ((b'a', b'b'), (b'ab',)),
             ((1,), (b'1',)),
             ((1,), ('1',)),
             (([1, 2], 3), (1, [2, 3])),
             ((b'',), ()),
             ((b'x\x00y',), (b'x\x00z',))]
    for a, b in pairs:
        check(C.cat(G, *a) != C.cat(G, *b), f"cat{a!r} != cat{b!r}")
    check(C.cat(G, sch.g1) != C.cat(G, G.init(ZR, 1)), "a G1 element and a ZR element encode differently")
    try:
        C.to_bytes(G, True)
        check(False, "bool is rejected by the encoder")
    except TypeError:
        check(True, "bool is rejected by the encoder")

    # --- 3. Hash-to-group reads the whole input, including after a zero byte
    h1 = C.hash_to_g1(G, b'HC', b'CERT', b'prefix\x00one')
    h2 = C.hash_to_g1(G, b'HC', b'CERT', b'prefix\x00two')
    check(h1 != h2, "hash_to_g1 distinguishes inputs that differ only after a zero byte")

    # --- 4. The certificate message binds d and C even if d contains a zero byte
    t = 0
    ell_t = sch.ell(t)
    d = b'\x00' * 32
    d2 = b'\x00' * 31 + b'\x01'
    C1 = sch.g1
    check(sch._cert_message_hash_ell(ell_t, C1, d) != sch._cert_message_hash_ell(ell_t, C1, d2),
          "HC(CERT||M_t) depends on d_t when d_t starts with a zero byte")
    check(sch._cert_message_hash_ell(ell_t, C1, d) != sch._cert_message_hash_ell(ell_t, C1 * sch.g1, d),
          "HC(CERT||M_t) depends on C_t when d_t starts with a zero byte")

    # --- 5. Label checks
    check(sch.ell(1) != sch.ell(2) and sch.ell(1) == sch.ell(1), "round labels are distinct and deterministic")
    R = sch.report(1, 7, 42)
    check(sch.verify_rep(R), "a report with a well-formed label verifies")
    bad = (R[0], R[1] + b'x', R[2], R[3], R[4])
    check(not sch.verify_rep(bad), "a report with a malformed label is rejected")

    print("\nALL PASSED" if not FAILS else f"\n{len(FAILS)} FAILED")
    return 0 if not FAILS else 1


if __name__ == '__main__':
    raise SystemExit(main())