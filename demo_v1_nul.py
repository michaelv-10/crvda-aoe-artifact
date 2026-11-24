"""Shows the zero-byte truncation in hash_to_g1 of version 1.0 (and that 2.0 fixes it).
Usage: python3 demo_v1_nul.py <folder containing crvda_aoe.py>"""
import sys
sys.path.insert(0, sys.argv[1])
import crvda_aoe_v2 as C
from charm.toolbox.pairinggroup import ZR

n, k, L = 5, 1, 8
tries = 0
for s in range(400):
    sch = C.CRVDA_AOE('BN254'); sch.setup(n, k, L, sid=f"demo-{s}".encode()); sch.build_bsgs()
    for t in range(3):
        tries += 1
        xs = [7 * i for i in range(1, n + 1)]
        reps = [sch.report(i, t, xs[i - 1]) for i in range(1, n + 1)]
        T, Ct, d = sch.build(t, reps)
        if b'\x00' not in sch.rid and b'\x00' not in d:
            continue
        shares = {j: sch.cert_share(j, t, T, Ct, d) for j in sch.Q}
        G = sch.cert_combine_gamma(t, Ct, d, shares)
        C2 = Ct * sch.g1                                  # aggregate for sum + 1
        G2 = (G[0], G[1], C2, G[3])
        print(f"after {tries} round(s): zero byte in {'rid' if b'\x00' in sch.rid else 'd_t'}")
        print("  VerifyCert(Gamma with altered C_t):", sch.verify_gamma(G2))
        if sch.verify_gamma(G2):
            X2, Z2 = sch.aggr_dec_gamma(G2)
            pi = sch.dec_prove(G2, X2, Z2)
            print(f"  Verify(Omega) for X = {X2} (true sum {sum(xs)}):",
                  sch.verify_omega((G2, X2, Z2, pi)))
        sys.exit(0)
print(f"no zero byte in rid or d_t in {tries} rounds")