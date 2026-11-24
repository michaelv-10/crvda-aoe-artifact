# CRVDA-AOE: artifact

This artifact contains the code and raw results for the paper "Collusion-Resistant
Privacy-Preserving Data Aggregation, Revisited". It covers the implementation and evaluation in
Section 7 and the appendix tables and figures listed below. Every table and figure of the
evaluation can be regenerated from the raw CSV files in `results/`. Rerunning the experiments
reproduces the raw files, within the variation stated in Section 8.

Table and figure numbers refer to the submitted PDF.

## 1. Contents and versions

| Path | Content |
|---|---|
| `crvda_aoe.py` | CRVDA-AOE prototype, **version 2.0** (corrected hashing, see Section 10) |
| `benchmarked/crvda_aoe.py` | **version 1.0**, which produced every timing in the paper |
| `crvda_wire.py` | wire codec: the byte encoding of every message (all sizes in the paper) |
| `e2e_round.py`, `section2_validate.py`, `section3_components.py`, `section4_scaling.py`, `section5_network.py`, `concurrency_test.py` | experiment scripts (Section 5) |
| `vpmda.py`, `lvp2da.py`, `masquerade.py` | re-implementations of the baseline schemes |
| `test_proofs.py`, `test_hashing.py`, `demo_v1_nul.py` | correctness tests (Section 3) and the version 1.0 demonstration (Section 10) |
| `make_tex_figures.py`, `make_fig_scaling.py`, `make_ablation.py`, `make_comparison.py`, `make_storage.py` | regenerate tables and figures from `results/` (Section 6) |
| `results/` | the raw measurements reported in the paper, all produced with version 1.0 |

`crvda_aoe.__version__` is `'2.0'`, and `crvda_aoe.BENCHMARKED_VERSION` is `'1.0'`.

The experiment scripts use the `crvda_aoe.py` in their own folder, so run as shipped they use
version 2.0. To rerun them with version 1.0, make a separate copy of the artifact and copy
`benchmarked/crvda_aoe.py` over `crvda_aoe.py` in that copy. Version 1.0 contains the hashing flaw
described in Section 10 and is included only to document the measurements.

## 2. Environment used for the paper

| Item | Value |
|---|---|
| Machine | Apple M4 (4.5 GHz; 4 performance + 6 efficiency cores), 16 GB RAM |
| OS | macOS 27.0.1 (arm64) |
| Python | 3.14.2 |
| Charm | charm-crypto-framework 0.62 |
| Pairing backend | PBC 1.0.0 (Homebrew bottle) |
| Big integers (baselines) | gmpy2 2.3.0 (GMP) |
| Curves | BN254 Type-3 pairing (CRVDA-AOE, VPMDA); secp224r1 through Charm ECGroup / OpenSSL (LV-P2DA) |
| Other packages | psutil, openpyxl, matplotlib (exact versions in `requirements.txt`) |

The correctness tests of version 2.0 also pass on Linux (Ubuntu 24.04, x86-64, Python 3.13), with
PBC built from source.

## 3. Installation and quick check

```
brew install pbc gmp            # macOS: PBC 1.0.0, GMP (on Linux, install GMP and build PBC from source)
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt # charm-crypto-framework==0.62, gmpy2==2.3.0, psutil, openpyxl, matplotlib
```

Run the quick check first. It takes less than a minute:

```
python3 test_proofs.py                      # 38 checks of the linking and range proofs; all PASS
python3 test_hashing.py                     # 21 checks of the version 2.0 hashing changes; all PASS
python3 section2_validate.py --part wire    # one complete round over the wire, 40 checks; all PASS
```

The first check includes an out-of-range report of a corrupted meter, which the range proof must
reject. The third check runs a complete round in which every party works on decoded messages. It
checks accepted and tampered messages, a repeated Report, which must return identical bytes, and
all message sizes: report 934 B, Gamma_t 100 B and Omega_t 296 B.

## 4. Inputs

The smart-meter readings used in the paper are 1,000 anonymized 30-minute readings in kWh, one per
meter. An industry partner provided them under a confidentiality agreement, so **they are not
included**.

All scripts run without them. Without `--data`, they use uniformly random L-bit inputs. The
measured costs do not depend on the input values, because every proof and check depends only on
n, k and L. In the paper, one certifier's GoodTrans takes 60.03 s with random inputs (Table 6) and
60.04 s with the real readings (Table 4). The L-sweep and the concurrency test already used random
inputs in the paper.

To use your own readings, pass an Excel file with one column of non-negative values with
`--data <file.xlsx>`. The scripts scale each value by 10^3 (`--decimals 3`) and encode it as an
L-bit integer. A round with n meters uses the first n values.

Fixed settings: L = 16, k = 20% of n, seed 1234. Each run uses one warm-up round, then
10/10/10/5/3/3 trials for n = 50/100/250/500/750/1000.

## 5. Experiments

Each script writes to the output folder shown, in the artifact root. The shipped results in
`results/` are not overwritten. The longest experiment is the single round with all 201
certifiers, which executes every certifier one after another (its measured serial time is
12,439 s, about 3.5 h; Table 5).

| Step | Command | Output folder | Paper |
|---|---|---|---|
| Complete rounds (n-sweep) | `python3 e2e_round.py` | `e2e_results/` | Tables 1, 5; Fig. 2(a, b) |
| Complete round with all 201 certifiers | `python3 e2e_round.py --n 1000 --trials 1 --all-certifiers-up-to 1000 --out e2e_allcert` | `e2e_allcert/` | Table 1 (row n = 1,000\*), Table 5 (last row) |
| Validation, sizes, storage, memory | `python3 section2_validate.py` | `s2_results/` | Table 9; Fig. 2(c, d); message sizes |
| Components and rejection tests | `python3 section3_components.py` | `s3_results/` | Tables 1, 4; C1–C4 in Section 7.4 |
| k- and L-sweeps (n = 200) | `python3 section4_scaling.py --part k`, then `--part L` | `s4_results/` | Tables 7, 8 |
| Network model | `python3 section5_network.py --e2e-dir e2e_results` | `s5_results/` | Fig. 1 |
| Concurrent certifiers | `python3 concurrency_test.py --out concurrency_results` | `concurrency_results/` | Table 6 |
| VPMDA | `python3 vpmda.py --bench --variant extended` (repeat with `--variant main`) | `vpmda_results_<variant>/` | Tables 11, 12 |
| LV-P2DA | `python3 lvp2da.py --bench` | `lvp2da_results_secp224r1_batch/` | Tables 11, 12 |
| Masquerade | `python3 masquerade.py --bench` | `masquerade_results/` | Tables 11, 12 |

Every long-running script accepts `--smoke`, which runs a small instance in under a minute. Each
baseline also has a `--check` mode, a self-test of its correctness and its stated limits.
`e2e_round.py` accepts `--resume` to continue an interrupted run. On macOS,
`caffeinate -i python3 <script>` keeps the machine awake during long runs.

## 6. Regenerating tables and figures from the shipped results

These scripts read `results/`, take seconds and need no Charm installation; `section5_network.py`
also needs matplotlib.

```
python3 section5_network.py --e2e-dir results/e2e_results --out results/s5_results   # data of Fig. 1
python3 make_tex_figures.py        # latex/fig2_round.tex  = Fig. 1 (estimated round delay)
python3 make_fig_scaling.py        # latex/fig_scaling.tex = Fig. 2 (scaling with n)
python3 make_ablation.py --s3 results/s3_results/s3_components.csv               # C1-C4, Section 7.4
python3 make_storage.py --crvda results/s2_results/s2_storage.csv                # Table 9
python3 make_comparison.py --crvda results/e2e_results/e2e_summary.csv \
    --vpmda-ext results/vpmda_results_extended/vpmda_summary.csv \
    --vpmda-main results/vpmda_results_main/vpmda_summary.csv \
    --masquerade results/masquerade_results/masquerade_summary.csv \
    --lvp2da results/lvp2da_results_secp224r1_batch/lvp2da_summary.csv          # Table 12
```

`make_tex_figures.py` also writes three figures of an earlier draft, which are not in the paper:
`fig1_certifier.tex`, `fig3_scaling_n.tex` and `fig4_cost_of_k.tex`. Tables 4–8 list values
directly from the CSV files named in Section 5. Tables 3 and 10 contain no measured values.

## 7. Measurement method

- **Timing.** Wall-clock time is measured with `time.perf_counter` and CPU time with
  `time.process_time`. One process executes everything sequentially.
- **Reported statistic.** The median with the interquartile range. Raw per-trial values are stored
  unrounded in the `*_trials.csv` files.
- **What is included.** Stage times include serialization, hashing and Fiat–Shamir challenges.
  Setup and the baby-step giant-step (BSGS) table are timed separately and excluded from per-round
  figures.
- **Critical path.** The critical path is derived from measured stage times under the intended
  parallelism, with zero network delay. It is not a measured distributed run. When only one
  certifier was executed (n > 100 in the sweep), serial time and total CPU are derived as (k + 1)
  times that certifier's measured cost.
- **Network delay.** Estimated from a model (`section5_network.py`), not measured.
- **Memory.** Each role runs in a fresh process, and its RSS is sampled every 2 ms with psutil.
- **Sizes.** All sizes are byte lengths from the wire codec in `crvda_wire.py`, which uses
  compressed points.

## 8. Expected variation

On the same machine, stage totals reproduce within about 1%; their IQRs are below 1% of the median.
Per-meter report time drifts by up to about 4% between runs. Absolute times on other hardware will
differ. The ratios between stages, the operation counts and all byte sizes should not change; byte
sizes are deterministic.

Run as shipped, the scripts measure version 2.0. Its extra hashing work is small, so its timings
should agree with those of version 1.0 within the variation above, but the paper reports
version 1.0.

## 9. Known deviations

- The Masquerade results in the paper used |N| = 2047 bits. The current `masquerade.py` generates
  exactly 2048 bits.
- When `e2e_round.py` logs Omega_t, it sizes X_t minimally (295 B for n <= 250). The paper uses
  the codec's fixed 4-byte X_t (296 B), which is also what `section2_validate.py` reports.
- `make_storage.py` reports the DC's BSGS table in a compact encoding, 291,492 B: a 32-byte point and
  a 4-byte index per entry. Table 9 reports the table as implemented, 404,850 B with Charm-serialized
  keys. The paper gives both.

## 10. Version 2.0: changes to hashing

Version 2.0 changes only the way hash inputs are formed. The protocol, the challenge inputs (domain
tags, session identifier, round label, meter identity, statement and earlier proof messages) and
every message exchanged between parties are unchanged.

1. **Fiat–Shamir challenges are uniform in Z_p** (`fs_challenge`). Version 1.0 reduced one SHA-256
   digest modulo p, which is not exactly uniform. Version 2.0 uses rejection sampling:
   - let p = `group.order()`, M = 2^256 and L0 = floor(M/p)·p;
   - for counter = 0, 1, 2, …: compute
     v = SHA-256(`"CRVDA-AOE/H_FS/v2"` ‖ counter as 4 bytes ‖ encoding of the inputs);
   - if v < L0, output v mod p; otherwise increment the counter and repeat.

   For Charm's BN254 group, a draw is rejected with probability about 1.6%. This applies to every
   challenge: Schnorr signatures, linking proofs, Bulletproofs (y, z, x, w and the inner-product
   rounds) and the recovery proof.
2. **Hash inputs use an unambiguous encoding** (`to_bytes`, `cat`). Every value is encoded as a
   1-byte type tag, an 8-byte big-endian length and the payload:
   - B: bytes;
   - S: UTF-8 string;
   - I: signed big-endian integer;
   - L: list, where the length is the number of elements, followed by the encoded elements;
   - D: dict, encoded as its (key, value) pairs sorted by encoded key;
   - E: group or scalar element, using Charm's serialization, which starts with the group type.

   Version 1.0 joined values with `|` and `||` and wrote integers in decimal, so different inputs
   could produce the same bytes.
3. **Hash-to-group hashes the whole input** (`hash_to_g1`). Charm's `group.hash` stops reading a
   bytes input at its first zero byte. Version 1.0 placed raw SHA-256 digests (the roster digest rid
   and the transcript digest d_t) inside hash-to-group inputs.
   - When rid or d_t contained a zero byte, the input of H_C(CERT ‖ M_t) was cut off before d_t and
     C_t, so the certificate did not bind them.
   - This happens in about 12% of rounds because of d_t. If rid contains a zero byte (about a 12%
     chance), it affects every round of the session.
   - The flaw affected the prototype, not the protocol or its analysis, and it does not change the
     work performed or the measured costs.
   - Version 2.0 passes the base64 encoding of the unambiguous input, which contains no zero byte.

   To reproduce the effect:
   ```
   mkdir v1 && cp benchmarked/crvda_aoe.py v1/
   python3 demo_v1_nul.py v1     # 1.0: a certificate with an altered C_t and a wrong sum are accepted
   python3 demo_v1_nul.py .      # 2.0: the altered certificate is rejected
   ```

Message sizes are the same in both versions:
- report: 934 B;
- transcript message: 68 + n·934 B;
- Gamma_t: 100 B;
- Omega_t: 296 B.

Version 2.0 was checked with the quick check of Section 3, `sanity_check()` in `crvda_aoe.py`, and
the `--smoke` runs of `e2e_round.py` and `concurrency_test.py`. It was not re-benchmarked.

**Deployment note.** Privacy relies on the encrypt-once rule: an honest meter must never encrypt two
values under the same round label. The prototype keeps its report cache in memory, which is
sufficient for a single process. A deployed meter must keep this cache in storage that survives
restarts.

## 11. Licence

The code is released under the MIT licence (see `LICENSE`). Charm, PBC and the other dependencies
are used under their own licences and are not included.
