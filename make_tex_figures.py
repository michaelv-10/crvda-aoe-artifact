"""
make_tex_figures.py -- pgfplots code for Figs. 1-4 of Section XI, with every plotted value
taken from the CSV files in results/ (the same files as the paper's tables).

  Fig. 1: (a) GoodTrans per report, (b) certifier memory -- single column, stacked vertically
  Fig. 2: critical path of a complete round, n = 1000 -- single column
  Fig. 3: four panels in one row (figure*)
  Fig. 4: four panels in one row (figure*)
"""
import csv
import os

H = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(H, 'results')
OUT = os.path.join(H, 'latex')
os.makedirs(OUT, exist_ok=True)


# Folder of each result file inside results/ (the artifact layout).
FOLDER = {'e2e_summary.csv': 'e2e_results', 'e2e_network.csv': 'e2e_results',
          's2_memory.csv': 's2_results', 's2_sizes.csv': 's2_results',
          's3_components.csv': 's3_results', 's4_k_summary.csv': 's4_results',
          's5_network.csv': 's5_results'}


def rows(name):
    """Read results/<folder>/<name>, with the folder given by FOLDER."""
    with open(os.path.join(D, FOLDER[name], name)) as f:
        return list(csv.DictReader(f))


def fmt(x, d):
    return f"{x:.{d}f}"


# ------------------------------------------------------------------ data
E = sorted(rows('e2e_summary.csv'), key=lambda r: int(r['n']))
NET_E = rows('e2e_network.csv')
S3 = {}
for r in rows('s3_components.csv'):
    S3.setdefault(int(r['n']), {})[r['component']] = float(r['median_ms'])
MEM = [r for r in rows('s2_memory.csv') if r['role'] == 'certifier']
MEM.sort(key=lambda r: int(r['n']))
K = sorted(rows('s4_k_summary.csv'), key=lambda r: int(r['k']))
S5 = rows('s5_network.csv')
SZ = {int(r['n']): r for r in rows('s2_sizes.csv')}

preamble = r"""% ---- add to the preamble of the IEEEtran paper ----
\usepackage{pgfplots}
\pgfplotsset{compat=1.18}
\usetikzlibrary{patterns}
\usepackage[caption=false,font=footnotesize]{subfig}
\definecolor{cBlue}{HTML}{2A78D6}    % GoodTrans / main series
\definecolor{cOrange}{HTML}{EB6834}  % CertCombine / second series
\definecolor{cGreen}{HTML}{1BAF7A}   % other measured stages / third series
\definecolor{cGrey}{HTML}{BDBCB6}    % network (estimated)
\definecolor{cInk}{HTML}{52514E}
\pgfplotsset{crvda/.style={
    tick label style={font=\scriptsize}, label style={font=\scriptsize},
    title style={font=\scriptsize, align=center}, legend style={font=\scriptsize},
    axis lines*=left, tick align=outside, major tick length=2pt,
    ymajorgrids, grid style={black!12}, every axis plot/.append style={line width=0.9pt},
    scaled ticks=false}}
"""

# ------------------------------------------------------------------ Fig. 1
c = S3[1000]
n = 1000
rest = c['gt_other'] + c['gt_aggcheck'] + c['gt_digest'] + c['certshare_bls_sign']
parts = [('Range-proof verify', c['gt_range_verify'] / n),
         ('Linking-proof verify', c['gt_link_verify'] / n),
         ('Signature verify', c['gt_sig_verify'] / n),
         ('Label hash', c['gt_label_hash'] / n),
         ('Roster, digest, BLS share', rest / n)]
tot = sum(v for _, v in parts)
names = [p[0] for p in parts][::-1]
coords_a = ' '.join(
    f"({v:.4f},{i}) [{(f'{v:.2f}' if v >= 1 else f'{v:.3f}')} ms ({100 * v / tot:.1f}\\%)]"
    for i, (_, v) in enumerate(parts[::-1]))
ns = [int(r['n']) for r in MEM]
inp = [float(r['input_MiB']) for r in MEM]
wrk = [float(r['working_MiB']) for r in MEM]
coords_in = ' '.join(f"({nn},{a:.4f})" for nn, a in zip(ns, inp))
coords_wk = ' '.join(f"({nn},{b:.4f}) [{a + b:.1f}]" for nn, a, b in zip(ns, inp, wrk))
fig1 = rf"""% Fig. 1 -- certifier bottleneck (n = 1000, k = 200). Values: s3_components.csv, s2_memory.csv
\begin{{figure}}[!t]
\centering
\subfloat[GoodTrans cost per report by component, n = 1000 (total {tot:.1f}~ms).]{{%
\begin{{tikzpicture}}
\begin{{axis}}[crvda, xbar, width=0.62\columnwidth, height=3.6cm, scale only axis,
  bar width=7pt, xmin=0, xmax={max(v for _, v in parts) * 1.62:.1f},
  ytick={{0,...,4}}, yticklabels={{{', '.join(names)}}}, ymajorgrids=false, xmajorgrids,
  y axis line style={{draw=none}}, ytick style={{draw=none}},
  xlabel={{Time per report (ms)}},
  point meta=explicit symbolic, nodes near coords, nodes near coords align={{horizontal}},
  every node near coord/.append style={{font=\tiny, black}}]
\addplot[fill=cBlue, draw=none] coordinates {{{coords_a}}};
\end{{axis}}
\end{{tikzpicture}}%
\label{{fig:certifier-a}}}}

\subfloat[Certifier memory during GoodTrans, above the process baseline (k = 0.2n).]{{%
\begin{{tikzpicture}}
\begin{{axis}}[crvda, ybar stacked, width=0.8\columnwidth, height=3.4cm, scale only axis,
  bar width=11pt, ymin=0, ymax={(inp[-1] + wrk[-1]) * 1.25:.1f},
  symbolic x coords={{{','.join(str(x) for x in ns)}}}, xtick=data, enlarge x limits=0.1,
  xlabel={{Meters $n$ ($k = 0.2n$)}}, ylabel={{MiB above baseline}},
  legend style={{at={{(0.02,0.98)}}, anchor=north west, draw=none, fill=none}}, legend cell align=left]
\addplot[fill=cBlue, draw=none] coordinates {{{coords_in}}};
\addplot[fill=cOrange, draw=none, point meta=explicit symbolic, nodes near coords,
  every node near coord/.append style={{font=\tiny, black, anchor=south}}] coordinates {{{coords_wk}}};
\legend{{Transcript input held, Peak working memory}}
\end{{axis}}
\end{{tikzpicture}}%
\label{{fig:certifier-b}}}}
\caption{{Certifier bottleneck. (a) GoodTrans cost per report by component at $n = 1000$, $k = 200$ (medians of three rounds of 1,000 reports). (b) Certifier memory during GoodTrans, above the process baseline: the transcript held in memory and the peak working memory beyond it.}}
\label{{fig:certifier}}
\end{{figure}}
"""

# ------------------------------------------------------------------ Fig. 2
ORDER = ['report', 'net_upload', 'build', 'net_dist', 'goodtrans', 'net_shares',
         'certcombine', 'net_gamma', 'dc', 'net_omega', 'verify']
CAT = {'goodtrans': 'cBlue', 'certcombine': 'cOrange'}
recs = [r for r in S5 if r['n'] == '1000' and (float(r['rtt_ms']) == 0 or float(r['rtt_ms']) == 50)]
recs.sort(key=lambda r: float(r['total_ideal_ms']))
def lab(r):
    if float(r['rtt_ms']) == 0:
        return 'Compute only'
    return f"AG {float(r['B_ag_mbps']):g} / SM {float(r['B_m_mbps']):g} Mbps"
labels2 = [lab(r) for r in recs]
plots2 = []
seen = set()
for s_ in ORDER:
    if s_.startswith('net_'):
        cat, style = 'net', 'fill=cGrey, draw=white, postaction={pattern=north east lines, pattern color=white}'
        legend = 'Network (estimated)'
    elif s_ in CAT:
        cat, style = s_, f'fill={CAT[s_]}, draw=none'
        legend = {'goodtrans': 'GoodTrans + BLS share', 'certcombine': 'CertCombine'}[s_]
    else:
        cat, style = 'other', 'fill=cGreen, draw=none'
        legend = 'Report, Build, DC, Verify'
    pts = ' '.join(f"({float(r[s_ + '_ms']) / 1000:.4f},{i})" for i, r in enumerate(recs))
    if cat in seen:
        plots2.append(rf"\addplot[{style}, forget plot] coordinates {{{pts}}};")
    else:
        plots2.append(rf"\addplot[{style}] coordinates {{{pts}}};" + "\n" + rf"\addlegendentry{{{legend}}}")
        seen.add(cat)
totals2 = '\n'.join(rf"\node[anchor=west, font=\tiny] at (axis cs:{float(r['total_ideal_ms']) / 1000:.4f},{i}) {{{float(r['total_ideal_ms']) / 1000:.1f} s}};"
                    for i, r in enumerate(recs))
fig2 = rf"""% Fig. 2 -- critical path of a complete round, n = 1000, k = 200, RTT 50 ms (transfer-only network).
% Values: s5_network.csv (stage medians; network = RTT/2 + bytes/bandwidth per stage)
\begin{{figure}}[!t]
\centering
\begin{{tikzpicture}}
\begin{{axis}}[crvda, xbar stacked, width=0.6\columnwidth, height=4.6cm, scale only axis,
  bar width=7pt, xmin=0, xmax=335, ymin=-0.6, ymax={len(recs) - 0.4},
  ytick={{0,...,{len(recs) - 1}}}, yticklabels={{{', '.join(labels2)}}},
  ymajorgrids=false, xmajorgrids, y axis line style={{draw=none}}, ytick style={{draw=none}},
  xlabel={{Round delay (s), network estimated at RTT 50 ms}},
  extra x ticks={{300}}, extra x tick labels={{}},
  extra x tick style={{grid=major, major grid style={{cInk, dashed, line width=0.8pt}}}},
  legend style={{at={{(0.5,-0.32)}}, anchor=north, draw=none, legend columns=2, /tikz/every even column/.append style={{column sep=6pt}}}},
  legend cell align=left]
{chr(10).join(plots2)}
{totals2}
\node[anchor=south east, font=\tiny, cInk] at (axis cs:300,{len(recs) - 0.45}) {{5-min interval}};
\end{{axis}}
\end{{tikzpicture}}
\caption{{Critical path of a complete round by stage, $n = 1000$, $k = 200$. Computation segments are stage medians, and their sum ({float(recs[0]['total_ideal_ms']) / 1000:.1f}~s) differs from the median per-round bound in Table~VII by {abs(float(recs[0]['total_ideal_ms']) - float(E[-1]['parallel_compute_bound_ms_median'])) / float(E[-1]['parallel_compute_bound_ms_median']) * 100:.2f}\%. Network segments are transfer-only estimates at RTT = 50~ms. The dashed line marks the 5-minute settlement interval.}}
\label{{fig:round}}
\end{{figure}}
"""

# ------------------------------------------------------------------ Fig. 3
nn = [int(r['n']) for r in E]
def ecoords(key, scale, iqr=True):
    out = []
    for r in E:
        m = float(r[key + '_median']) / scale
        if iqr:
            lo, hi = float(r[key + '_q1']) / scale, float(r[key + '_q3']) / scale
            out.append(f"({r['n']},{m:.4f}) += (0,{hi - m:.4f}) -= (0,{m - lo:.4f})")
        else:
            out.append(f"({r['n']},{m:.4f})")
    return ' '.join(out)
def netcoords(bw, rtt):
    pts = []
    for r in E:
        mm = [x for x in NET_E if x['n'] == r['n'] and float(x['bandwidth_mbps']) == bw and float(x['rtt_ms']) == rtt]
        pts.append(f"({r['n']},{float(mm[0]['parallel_total_ms']) / 1000:.4f})")
    return ' '.join(pts)
cpu_h = ' '.join(f"({r['n']},{float(r['total_cpu_ms_median']) / 3.6e6:.4f})" for r in E)
agq = ' '.join(f"({r['n']},{(int(r['k']) + 1) * int(SZ[int(r['n'])]['dist_msg_B']) / 1e6:.4f})" for r in E)
panel = r"""\subfloat[%s]{%%
\begin{tikzpicture}
\begin{axis}[crvda, width=0.185\textwidth, height=2.9cm, scale only axis, xmin=0, xmax=1050, ymin=0,
  xtick={0,250,500,750,1000}, xlabel={Meters $n$}, ylabel={%s}%s]
%s
\end{axis}
\end{tikzpicture}%%
\label{%s}}"""
p_a = panel % ("One certifier: GoodTrans + BLS share", "Time (s)", "",
               rf"\addplot[cBlue, mark=*, mark size=1.4pt, error bars/.cd, y dir=both, y explicit] coordinates {{{ecoords('certshare_one_ms', 1000)}}};",
               "fig:scaling-a")
p_b = panel % ("Parallel bound, without and with network", "Time (s)",
               ", legend style={at={(0.02,0.98)}, anchor=north west, draw=none, fill=none, font=\\tiny}, legend cell align=left",
               rf"\addplot[cBlue, mark=*, mark size=1.4pt] coordinates {{{ecoords('parallel_compute_bound_ms', 1000, iqr=False)}}};" + "\n"
               + rf"\addplot[cOrange, dashed, mark=square*, mark size=1.3pt] coordinates {{{netcoords(100, 50)}}};" + "\n"
               + rf"\addplot[cGreen, dashed, mark=triangle*, mark size=1.6pt] coordinates {{{netcoords(10, 50)}}};" + "\n"
               + r"\legend{Compute only, + 100 Mbps, + 10 Mbps}",
               "fig:scaling-b")
p_c = panel % ("Total CPU work, all parties", "CPU time (h)", "",
               rf"\addplot[cBlue, mark=*, mark size=1.4pt] coordinates {{{cpu_h}}};", "fig:scaling-c")
p_d = panel % ("AG-to-quorum traffic", "MB per round", "",
               rf"\addplot[cBlue, mark=*, mark size=1.4pt] coordinates {{{agq}}};", "fig:scaling-d")
fig3 = rf"""% Fig. 3 -- scaling with n (k = 0.2n, L = 16). Values: e2e_summary.csv, e2e_network.csv, s2_sizes.csv
\begin{{figure*}}[!t]
\centering
{p_a}\hfill
{p_b}\hfill
{p_c}\hfill
{p_d}
\caption{{Scaling with $n$ ($L = 16$, $k = 0.2n$; medians, with IQR bars smaller than the markers). (a) One certifier's GoodTrans and BLS share. (b) Parallel lower bound per round, alone and with transfer-only network delay on symmetric 100~Mbps and 10~Mbps links at RTT = 50~ms. (c) Total CPU work of all parties. (d) AG-to-quorum traffic.}}
\label{{fig:scaling}}
\end{{figure*}}
"""

# ------------------------------------------------------------------ Fig. 4
def kcoords(key, scale, iqr=True, d=3):
    out = []
    for r in K:
        m = float(r[key + '_median']) / scale
        lab_ = f"{m:.3g}"
        if iqr:
            lo, hi = float(r[key + '_q1']) / scale, float(r[key + '_q3']) / scale
            out.append(f"({r['k']},{m:.4f}) += (0,{hi - m:.4f}) -= (0,{m - lo:.4f}) [{lab_}]")
        else:
            out.append(f"({r['k']},{m:.4f}) [{lab_}]")
    return ' '.join(out)
def kmax(key, scale):
    return max(float(r[key + '_median']) for r in K) / scale * 1.22
kpanel = r"""\subfloat[%s]{%%
\begin{tikzpicture}
\begin{axis}[crvda, ybar, width=0.185\textwidth, height=2.9cm, scale only axis, bar width=8pt,
  ymin=0, ymax=%.3f, symbolic x coords={0,20,40,60}, xtick=data, enlarge x limits=0.18,
  xlabel={Collusion threshold $k$}, ylabel={%s},
  point meta=explicit symbolic, nodes near coords, every node near coord/.append style={font=\tiny, black, yshift=1pt}]
\addplot[fill=cBlue, draw=none%s] coordinates {%s};
\end{axis}
\end{tikzpicture}%%
\label{%s}}"""
eb = ", error bars/.cd, y dir=both, y explicit, error bar style={cInk}"
q_a = kpanel % ("CertCombine latency", kmax('certcombine_ms', 1000), "Time (s)", eb, kcoords('certcombine_ms', 1000), "fig:k-a")
q_b = kpanel % ("AG-to-quorum traffic", kmax('agq_traffic_B', 1e6), "MB per round", "", kcoords('agq_traffic_B', 1e6, iqr=False), "fig:k-b")
q_c = kpanel % ("Total certifier CPU work", kmax('cert_all_cpu_ms', 1000), "CPU time (s)", eb, kcoords('cert_all_cpu_ms', 1000), "fig:k-c")
q_d = kpanel % ("One certifier's GoodTrans", kmax('certshare_one_ms', 1000), "Time (s)", eb, kcoords('certshare_one_ms', 1000), "fig:k-d")
fig4 = rf"""% Fig. 4 -- cost of the collusion threshold k at n = 200 (L = 16). Values: s4_k_summary.csv
\begin{{figure*}}[!t]
\centering
{q_a}\hfill
{q_b}\hfill
{q_c}\hfill
{q_d}
\caption{{Cost of the collusion threshold $k$ at $n = 200$, $L = 16$: CertCombine latency, AG-to-quorum traffic, total certifier CPU work and one certifier's GoodTrans time (medians of 10 rounds, with IQR whiskers).}}
\label{{fig:cost-k}}
\end{{figure*}}
"""

demo = r"""\documentclass[journal]{IEEEtran}
\input{preamble}
\usepackage{lipsum}
\begin{document}
\title{Figure layout check}
\maketitle
\lipsum[1-2]
\input{fig1_certifier}
\lipsum[3-4]
\input{fig2_round}
\lipsum[5-6]
\input{fig3_scaling_n}
\lipsum[7-9]
\input{fig4_cost_of_k}
\lipsum[10-14]
\end{document}
"""
for name, txt in [('preamble.tex', preamble), ('fig1_certifier.tex', fig1), ('fig2_round.tex', fig2),
                  ('fig3_scaling_n.tex', fig3), ('fig4_cost_of_k.tex', fig4), ('main_demo.tex', demo)]:
    with open(os.path.join(OUT, name), 'w') as f:
        f.write(txt)
print('wrote', OUT)