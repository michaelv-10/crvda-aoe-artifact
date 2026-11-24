"""
make_storage.py -- persistent storage by role for CRVDA-AOE and the three baselines
====================================================================================

Roles for CRVDA-AOE: ordinary SM, quorum SM
(certifier, incl. the roster it needs for GoodTrans), AG, DC, public verifier.

CRVDA-AOE   taken from s2_storage.csv (written by section2_validate.py from the codec)
Baselines   object lists read off the re-implementations (vpmda.py, lvp2da.py,
            masquerade.py), at the parameters actually benchmarked:
  VPMDA [16]      Paillier |N| = 2048 (Z_N 256 B, Z_N^2 512 B), BN254 compressed
                  (G1 32 B, G2 64 B, Z_p 32 B), k = 1 data type, sk_prg 32 B,
                  omega = 2k integers stored in 8 B each
    SM_i          gamma_i (Z*_N) + N + nu (G1) + H(att_i) (G1) + omega
    AG            N + sk_prg + main: beta_i in G2 for all n | extended: psi_i in Z_p for all n
    CC            gamma_0 (mod lambda, |N|) + sk_prg + N + rho (G2) + nu (G1) + omega
                  + H(att_i) for all n (G1) + main: beta_i for all n (G2) | extended: beta (G2)
  LV-P2DA [41]    secp224r1: point 29 B (compressed), scalar 28 B, ID 4 B
    SM            ID + x + e + D + pk + W + public (P, P_pub)
    BS            own (ID, x, e, D, pk) + public (P, P_pub) + (ID_i, pk_i) of all n meters
    ESP           own (ID, x, e, D, pk) + public + (ID, pk) of the BS
                  + BSGS table over [0, n(2^L - 1)]: isqrt(n(2^L - 1)) + 1 entries x (29 B point + 4 B index)
  Masquerade [19] |N| = 2048 nominal (N 256 B; N^2, e, g_m 512 B each; the run's |N| = 2047 gives the same byte lengths)
    participant   pk = (N, e, g_m)                    (no long-term secret; randomness is fresh per round)
    curator       pk
    analyst       pk + sk = (lambda, mu, d), 256 B each
    auditor       pk
    ledger        per round: n commitments c_i + (ct_sum, r_sum) + analyst output   (public, grows per round)

System-wide total (X-D): S_total(n) = n * S_meter + (extra roles), every meter counted.

Usage: python3 make_storage.py --crvda s2_results/s2_storage.csv [--L 16] [--out s7_storage.csv]
"""
import argparse
import csv
import math

NGRID = [50, 100, 250, 500, 750, 1000]


def crvda(path):
    out = {}
    for r in csv.DictReader(open(path)):
        n = int(r['n'])
        d = out.setdefault(n, {'k': int(r['k'])})
        p, c, b = r['party'], r['component'], int(r['bytes'])
        if p == 'meter' and ('secret' in c or 'public data' in c):
            d['sm'] = d.get('sm', 0) + b
        elif p == 'meter' and 'generators' in c:
            d['sm_opt'] = b
        elif p == 'meter' and 'cached report' in c:
            d['sm_round'] = b
        elif p.startswith('certifier') and 'z_j' in c:
            d['q_key'] = b
        elif p.startswith('certifier') and 'roster' in c:
            d['roster'] = b
        elif p == 'AG' and 'public data' in c:
            d['ag'] = b
        elif p == 'AG' and 'archived' in c or (p == 'AG' and 'audit' in c):
            d['ag_round'] = b
        elif p == 'DC' and ('decryption key' in c or 'public data' in c):
            d['dc_keys'] = d.get('dc_keys', 0) + b
        elif p == 'DC' and 'compact' in c:
            d['dc_table'] = b
        elif p == 'verifier':
            d['ver'] = b
    return out


def rows_for(n, C, L):
    k = n // 5
    q = k + 1
    R = []

    def add(scheme, role, objects, size):
        R.append({'n': n, 'k': k, 'scheme': scheme, 'role': role, 'objects': objects, 'bytes': size})

    # ---- CRVDA-AOE (X-D roles) ----
    c = C[n]
    add('CRVDA-AOE', 'ordinary SM', 'keys (s_i, t_i, rho_i, rsk_i) + public data for Report', c['sm'])
    add('CRVDA-AOE', 'quorum SM, additional', 'certification key z_j', c['q_key'])
    add('CRVDA-AOE', 'certifier roster (local copy or public registry)', '(i, rvk_i, K_i) for all n', c['roster'])
    add('CRVDA-AOE', 'AG', 'header, g2, (j, W_j) for j in Q', c['ag'])
    add('CRVDA-AOE', 'DC', 'keys (s0, t0) + public data', c['dc_keys'])
    add('CRVDA-AOE', 'DC, BSGS table', 'compact table', c['dc_table'])
    add('CRVDA-AOE', 'public verifier', 'header, g1, S0, T0, g2, W_Q', c['ver'])
    tot = n * c['sm'] + q * (c['q_key'] + c['roster']) + c['ag'] + c['dc_keys'] + c['dc_table'] + c['ver']
    add('CRVDA-AOE', 'system total', 'n SM + (k+1)(z_j + roster) + AG + DC + verifier', tot)
    # registry variant (analytical): dealer publishes a 32 B roster digest; certifiers keep z_j + digest
    # and check fetched entries against it; one roster copy held by an untrusted registry
    DIG = 32
    add('CRVDA-AOE', 'quorum SM, registry variant', 'ordinary SM + z_j + roster digest', c['sm'] + c['q_key'] + DIG)
    reg = n * c['sm'] + q * (c['q_key'] + DIG) + c['roster'] + c['ag'] + c['dc_keys'] + c['dc_table'] + c['ver']
    add('CRVDA-AOE', 'system total, registry variant', 'n SM + (k+1)(z_j + digest) + 1 roster + AG + DC + verifier', reg)

    # ---- VPMDA ----
    ZN, G1, G2, ZP, PRG, OMEGA = 256, 32, 64, 32, 32, 2 * 8
    sm = ZN + ZN + G1 + G1 + OMEGA
    for var in ('main', 'extended'):
        s = f'VPMDA [16] ({var})'
        ag = ZN + PRG + (G2 * n if var == 'main' else ZP * n)
        cc = ZN + PRG + ZN + G2 + G1 + OMEGA + G1 * n + (G2 * n if var == 'main' else G2)
        add(s, 'SM', 'gamma_i, N, nu, H(att_i), omega', sm)
        add(s, 'AG', 'N, sk_prg, ' + ('beta_i (G2) for all n' if var == 'main' else 'psi_i (Z_p) for all n'), ag)
        add(s, 'CC', 'gamma_0, sk_prg, N, rho, nu, omega, H(att_i) for all n, '
            + ('beta_i for all n' if var == 'main' else 'beta'), cc)
        add(s, 'system total', 'n SM + AG + CC', n * sm + ag + cc)

    # ---- LV-P2DA ----
    PT, SC, ID = 29, 28, 4
    pub = 2 * PT
    own = ID + SC + SC + PT + PT                     # ID, x, e, D, pk
    sm = own + PT + pub                              # + W
    bs = own + pub + (ID + PT) * n
    entries = math.isqrt(n * (2 ** L - 1)) + 1
    esp_keys = own + pub + (ID + PT)
    esp_tab = entries * (PT + 4)
    add('LV-P2DA [41]', 'SM', 'ID, x, e, D, pk, W, P, P_pub', sm)
    add('LV-P2DA [41]', 'BS', 'own keys + (ID_i, pk_i) for all n', bs)
    add('LV-P2DA [41]', 'ESP', 'own keys + BS (ID, pk)', esp_keys)
    add('LV-P2DA [41]', 'ESP, BSGS table', f'{entries} entries x 33 B', esp_tab)
    add('LV-P2DA [41]', 'system total', 'n SM + BS + ESP', n * sm + bs + esp_keys + esp_tab)

    # ---- Masquerade ----
    N_, N2 = 256, 512
    pk = N_ + N2 + N2                                # N, e, g_m
    sk = 3 * N_                                      # lambda, mu, d
    rsum = (4096 + math.ceil(math.log2(max(n, 2))) + 7) // 8
    ledger = n * N2 + (N2 + rsum) + (8 + 6 * N2)
    add('Masquerade [19]', 'participant', 'pk = (N, e, g_m)', pk)
    add('Masquerade [19]', 'curator', 'pk', pk)
    add('Masquerade [19]', 'analyst', 'pk + sk (lambda, mu, d)', pk + sk)
    add('Masquerade [19]', 'auditor (public verifier)', 'pk', pk)
    add('Masquerade [19]', 'system total', 'n participants + curator + analyst + auditor', n * pk + pk + pk + sk + pk)
    add('Masquerade [19]', 'public ledger, per round', 'n commitments + (ct_sum, r_sum) + analyst output', ledger)
    return R


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument('--crvda', default='s2_results/s2_storage.csv')
    ap.add_argument('--L', type=int, default=16)
    ap.add_argument('--out', default='s7_storage.csv')
    a = ap.parse_args()
    C = crvda(a.crvda)
    rows = [r for n in NGRID for r in rows_for(n, C, a.L)]
    with open(a.out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    for r in rows:
        if r['n'] in (50, 1000):
            print(f"{r['n']:5d} {r['scheme']:26s} {r['role']:48s} {r['bytes']:>11,}")
    print('wrote', a.out)


if __name__ == '__main__':
    main()