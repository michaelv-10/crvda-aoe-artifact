"""
make_comparison.py -- Section 6 (part 1): role-by-role comparison of CRVDA-AOE and the baselines
================================================================================================

Reads the summary files (medians) of every scheme, all measured on the same Apple M4
with the same n grid, trial schedule, warm-up and readings, and writes one table per n.

Roles (each scheme's stages mapped onto them; see each *_env.txt for stage definitions)
  meter_ms        one meter's per-round computation
                    CRVDA-AOE report_single_median | VPMDA sm_total | Masquerade part_total | LV-P2DA sm_total
  aggregator_ms   aggregation side, including any verification of the inputs, for the
                  declared parallelism
                    CRVDA-AOE Build + one certifier's CertShare (k+1 run in parallel) + CertCombine
                    VPMDA ag_total | Masquerade cur_total | LV-P2DA bs_total
  decryptor_ms    party that recovers the aggregate
                    CRVDA-AOE DC (AggrDec incl. VerifyCert + DecProve) | VPMDA cc_total (verify + decrypt)
                    Masquerade ana_total | LV-P2DA esp_total
  public_verify_ms  public verification of the published result (empty: not provided)
                    CRVDA-AOE Verify(Omega) | Masquerade aud_total
  meter_msg_B     bytes sent by one meter
  agg_msg_B       bytes aggregator -> decryptor (Masquerade: curator -> ledger)
  public_out_B    published, publicly verifiable result

Usage
  python3 make_comparison.py --crvda e2e_results/e2e_summary.csv \
      --vpmda-ext vpmda_results_extended/vpmda_summary.csv --vpmda-main vpmda_results_main/vpmda_summary.csv \
      --masquerade masquerade_results/masquerade_summary.csv --lvp2da lvp2da_results_secp224r1_batch/lvp2da_summary.csv
Output: s6_comparison.csv
"""

import argparse
import csv


def read(p):
    return {int(r['n']): r for r in csv.DictReader(open(p))} if p else {}


def m(r, k):
    return float(r[k + '_median'])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument('--crvda', required=True)
    ap.add_argument('--vpmda-ext')
    ap.add_argument('--vpmda-main')
    ap.add_argument('--masquerade')
    ap.add_argument('--lvp2da')
    ap.add_argument('--out', default='s6_comparison.csv')
    a = ap.parse_args()
    C, VE, VM, MQ, LV = (read(a.crvda), read(a.vpmda_ext), read(a.vpmda_main), read(a.masquerade), read(a.lvp2da))
    rows = []
    for n in sorted(C):
        c = C[n]
        rows.append({'n': n, 'scheme': 'CRVDA-AOE', 'meter_ms': m(c, 'report_single_median_ms'),
                     'aggregator_ms': m(c, 'build_ms') + m(c, 'certshare_one_ms') + m(c, 'certcombine_ms'),
                     'decryptor_ms': m(c, 'dc_ms'), 'public_verify_ms': m(c, 'verify_ms'),
                     'meter_msg_B': 934, 'agg_msg_B': 100, 'public_out_B': 296,
                     'note': f"aggregator incl. one certifier's GoodTrans; total certifier CPU (k+1) x GoodTrans = "
                             f"{m(c, 'cert_all_cpu_ms') / 1000:.0f} s"})
        for name, D in (('VPMDA (extended)', VE), ('VPMDA (main)', VM)):
            if n in D:
                d = D[n]
                rows.append({'n': n, 'scheme': name, 'meter_ms': m(d, 'sm_total_ms'), 'aggregator_ms': m(d, 'ag_total_ms'),
                             'decryptor_ms': m(d, 'cc_total_ms'), 'public_verify_ms': '',
                             'meter_msg_B': m(d, 'sm_msg_B'), 'agg_msg_B': m(d, 'ag_msg_B'), 'public_out_B': '',
                             'note': 'CC verification needs CC secrets (not public)'})
        if n in MQ:
            d = MQ[n]
            rows.append({'n': n, 'scheme': 'Masquerade', 'meter_ms': m(d, 'part_total_ms'),
                         'aggregator_ms': m(d, 'cur_total_ms'), 'decryptor_ms': m(d, 'ana_total_ms'),
                         'public_verify_ms': m(d, 'aud_total_ms'),
                         'meter_msg_B': m(d, 'participant_to_curator_B') + m(d, 'participant_to_ledger_B'),
                         'agg_msg_B': m(d, 'curator_to_ledger_B'), 'public_out_B': m(d, 'analyst_to_ledger_B'),
                         'note': 'auditor is O(n): product of n commitments'})
        if n in LV:
            d = LV[n]
            rows.append({'n': n, 'scheme': 'LV-P2DA', 'meter_ms': m(d, 'sm_total_ms'), 'aggregator_ms': m(d, 'bs_total_ms'),
                         'decryptor_ms': m(d, 'esp_total_ms'), 'public_verify_ms': '',
                         'meter_msg_B': m(d, 'sm_msg_B'), 'agg_msg_B': m(d, 'bs_msg_B'), 'public_out_B': '',
                         'note': 'BS batch verification, l = 5'})
    with open(a.out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    for n in sorted({r['n'] for r in rows}):
        print(f"\nn = {n}")
        for r in rows:
            if r['n'] == n:
                pv = f"{r['public_verify_ms']:.1f}" if r['public_verify_ms'] != '' else '-'
                print(f"  {r['scheme']:18s} meter {r['meter_ms']:8.2f} ms | aggregator {r['aggregator_ms'] / 1000:8.3f} s | "
                      f"decryptor {r['decryptor_ms']:9.1f} ms | public verify {pv:>6} ms | meter {r['meter_msg_B']:.0f} B")
    print(f"\nwrote {a.out}")


if __name__ == '__main__':
    main()