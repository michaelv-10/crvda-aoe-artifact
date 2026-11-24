"""
make_ablation.py -- Section 6 (part 2): within-scheme breakdown of CRVDA-AOE
=============================================================================

Cumulative configurations, built ONLY from components measured in one run
(s3_results/s3_components.csv, medians; same machine, readings and trials):

  C1  AOE alone
      meter: AOE ciphertext C_i;  AG: product of the n ciphertexts;
      DC: mask Z_t + bounded discrete log
  C2  + reporting authentication and proofs
      meter: + commitment V_i, range proof, linking proof, report signature;
      the AG verifies every report (signature, label hashes, linking proof,
      range proof, roster/label checks) before aggregating
  C3  + quorum certification
      report verification moves to the k+1 certifiers (GoodTrans, in parallel);
      + transcript digest (Build), BLS share, CertCombine, and the DC's VerifyCert
      gate before decryption; + AG -> quorum transcript traffic
  C4  + public recovery verification  (= complete CRVDA-AOE)
      DC: + DecProve;  anyone: + Verify(Omega_t)

Metrics per configuration (n, k = 20% of n):
  latency_ms   compute-only critical path for the declared parallelism
               (meters in parallel; in C3/C4 the k+1 certifiers in parallel)
  cpu_ms       total computation of all parties (n meters, AG or k+1 certifiers, DC, verifier)
  bytes        all bytes sent in one round (encodings of Section 2)
  and the increments over the previous configuration.

Byte encodings: i 2 B, t 4 B, G1 32 B, digest 32 B.
  C1/C2 meter -> AG: (i, t, C_i) = 38 B  |  C2 report R_i = 934 B
  C1/C2 AG -> DC: (t, C_t) = 36 B
  C3 AG -> each certifier: 68 + n|R_i| B;  share 32 B;  Gamma_t 100 B
  C4 + Omega_t 296 B published

Security goals reached (explicitly NOT the complete protocol's goals before C4):
  C1  aggregator obliviousness of the BJL AOE only; no report authentication,
      no input-range guarantee, no aggregate integrity, no public verifiability
  C2  + authenticated, range-checked reports; a malicious AG can still omit,
      replace or mis-aggregate reports undetected (no aggregate integrity)
  C3  + aggregate integrity against a malicious AG colluding with up to k meters
      (quorum certificate); the recovered value is not publicly verifiable
  C4  all goals of CRVDA-AOE, incl. public verifiability of the recovered aggregate

Usage
  python3 make_ablation.py --s3 s3_results/s3_components.csv [--n 1000]
Outputs: s6_ablation.csv (all n), and a printed table for --n
"""

import argparse
import csv

ID, T, G1, DIG, REPORT, GAMMA, OMEGA = 2, 4, 32, 32, 934, 100, 296


def load(path):
    M = {}
    for r in csv.DictReader(open(path)):
        M.setdefault(int(r['n']), {'k': int(r['k'])})[r['component']] = float(r['median_ms'])
    return M


def configs(n, c):
    k = c['k']
    aoe = c['report_aoe_encrypt']
    proofs = c['report_commit'] + c['report_range_prove'] + c['report_link_prove'] + c['report_sign']
    report = aoe + proofs
    agg = c['gt_aggcheck']                                  # product of n ciphertexts
    verify_all = (c['gt_sig_verify'] + c['gt_label_hash'] + c['gt_link_verify']
                  + c['gt_range_verify'] + c['gt_other'])   # VerifyRep on all n reports
    dec = c['dc_mask'] + c['dc_dlog']
    build = agg + c['gt_digest']                            # Build: product + transcript digest
    certshare = c['certshare_total']                        # one certifier: GoodTrans + BLS share
    combine = c['certcombine_total']
    certcheck = c['dc_certcheck']
    decprove = c['dc_decprove']
    verify = c['verify_valid']

    out = []
    # C1
    out.append(('C1 AOE alone', 'AOE encryption; AG product; DC mask + discrete log',
                aoe + agg + dec,
                n * aoe + agg + dec,
                n * (ID + T + G1) + (T + G1)))
    # C2
    out.append(('C2 + reporting authentication and proofs',
                '+ commitment, range proof, linking proof, signature (meter); AG verifies all n reports',
                report + verify_all + agg + dec,
                n * report + verify_all + agg + dec,
                n * REPORT + (T + G1)))
    # C3
    dist = (k + 1) * (T + DIG + G1 + n * REPORT)
    out.append(('C3 + quorum certification',
                '+ Build digest, k+1 certifiers run GoodTrans + BLS share, CertCombine, VerifyCert gate; '
                'AG -> quorum transcripts',
                report + build + certshare + combine + certcheck + dec,
                n * report + build + (k + 1) * certshare + combine + certcheck + dec,
                n * REPORT + dist + (k + 1) * G1 + GAMMA))
    # C4
    out.append(('C4 + public recovery verification (complete CRVDA-AOE)',
                '+ DecProve (DC) and Verify(Omega) (anyone)',
                report + build + certshare + combine + certcheck + dec + decprove + verify,
                n * report + build + (k + 1) * certshare + combine + certcheck + dec + decprove + verify,
                n * REPORT + dist + (k + 1) * G1 + GAMMA + OMEGA))
    rows, prev = [], None
    goals = ['AO only', '+ authenticated, range-checked reports', '+ aggregate integrity (malicious AG + k meters)',
             '+ public verifiability (all goals)']
    for (name, added, lat, cpu, byt), g in zip(out, goals):
        r = {'n': n, 'k': k, 'configuration': name, 'added': added, 'latency_ms': lat, 'cpu_ms': cpu, 'bytes': byt,
             'd_latency_ms': lat - prev['latency_ms'] if prev else lat,
             'd_cpu_ms': cpu - prev['cpu_ms'] if prev else cpu,
             'd_bytes': byt - prev['bytes'] if prev else byt,
             'security_goals': g,
             'complete_protocol_goals': 'yes' if name.startswith('C4') else 'NO'}
        rows.append(r)
        prev = r
    return rows


def fmt_ms(v):
    return f"{v / 1000:.2f} s" if v >= 1000 else f"{v:.1f} ms"


def fmt_b(v):
    return f"{v / 1e6:.2f} MB" if v >= 1e6 else (f"{v / 1e3:.1f} KB" if v >= 1e3 else f"{v:.0f} B")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument('--s3', default='s3_results/s3_components.csv')
    ap.add_argument('--n', type=int, default=1000)
    ap.add_argument('--out', default='s6_ablation.csv')
    a = ap.parse_args()
    M = load(a.s3)
    rows = [r for n in sorted(M) for r in configs(n, M[n])]
    with open(a.out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    for r in rows:
        if r['n'] == a.n:
            print(f"{r['configuration']:58s} latency {fmt_ms(r['latency_ms']):>9} (+{fmt_ms(r['d_latency_ms']):>9}) | "
                  f"CPU {fmt_ms(r['cpu_ms']):>10} (+{fmt_ms(r['d_cpu_ms']):>10}) | bytes {fmt_b(r['bytes']):>9} "
                  f"(+{fmt_b(r['d_bytes']):>9}) | complete goals: {r['complete_protocol_goals']}")
    print(f"wrote {a.out}")


if __name__ == '__main__':
    main()