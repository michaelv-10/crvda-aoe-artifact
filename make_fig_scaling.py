"""
make_fig_scaling.py -- pgfplots code of the paper's scaling figure (Fig. 2, label fig:scaling),
with every plotted value taken from the result files:
  (a) one certifier's GoodTrans + BLS share   e2e_summary.csv  certshare_one_ms_median / 1000  (s)
  (b) CertCombine                             e2e_summary.csv  certcombine_ms_median / 1000    (s)
  (c) AG-to-quorum traffic per round           s2_sizes.csv     (k + 1) x dist_msg_B / 10^6      (MB)
  (d) memory above the process baseline        s2_memory.csv    input_MiB + working_MiB          (MiB)
      for the certifier and the aggregator
Usage:  python3 make_fig_scaling.py
"""
import csv
import os

H = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(H, 'results')
OUT = os.path.join(H, 'latex')


# Folder of each result file inside results/ (the artifact layout).
FOLDER = {'e2e_summary.csv': 'e2e_results', 'e2e_network.csv': 'e2e_results',
          's2_memory.csv': 's2_results', 's2_sizes.csv': 's2_results',
          's3_components.csv': 's3_results', 's4_k_summary.csv': 's4_results',
          's5_network.csv': 's5_results'}


def rows(name):
    """Read results/<folder>/<name>, with the folder given by FOLDER."""
    with open(os.path.join(D, FOLDER[name], name)) as f:
        return list(csv.DictReader(f))


def coords(pts, d):
    return ' '.join(f"({n},{v:.{d}f})" for n, v in pts)


def main():
    e2e = sorted(rows('e2e_summary.csv'), key=lambda r: int(r['n']))
    a = [(int(r['n']), float(r['certshare_one_ms_median']) / 1000) for r in e2e]
    b = [(int(r['n']), float(r['certcombine_ms_median']) / 1000) for r in e2e]
    sz = sorted(rows('s2_sizes.csv'), key=lambda r: int(r['n']))
    c = [(int(r['n']), (int(r['k']) + 1) * int(r['dist_msg_B']) / 1e6) for r in sz]
    mem = rows('s2_memory.csv')

    def memline(role):
        rs = sorted((r for r in mem if r['role'] == role), key=lambda r: int(r['n']))
        return [(int(r['n']), float(r['input_MiB']) + float(r['working_MiB'])) for r in rs]

    axis = (r"\begin{axis}[crvda, width=0.5\columnwidth, height=3.0cm, scale only axis=false, xmin=0, xmax=1050," "\n"
            r"  xtick={0,250,500,750,1000}, xlabel={Meters $n$}, ylabel={%s}, ymin=0%s]")
    tex = rf"""% Scaling with n (L = 16, k = 0.2n). Values: e2e_summary.csv (a, b), s2_sizes.csv (c), s2_memory.csv (d).
\begin{{figure}}[!t]
\centering
\subfloat[One certifier: GoodTrans + share (M)]{{\begin{{tikzpicture}}
{axis % ('Time (s)', '')}
\addplot[cBlue, mark=*, mark size=1.2pt] coordinates {{{coords(a, 4)}}};
\end{{axis}}\end{{tikzpicture}}}}\hfil
\subfloat[CertCombine, $k+1$ share checks (M)]{{\begin{{tikzpicture}}
{axis % ('Time (s)', '')}
\addplot[cOrange, mark=*, mark size=1.2pt] coordinates {{{coords(b, 4)}}};
\end{{axis}}\end{{tikzpicture}}}}\\
\subfloat[AG$\to$quorum traffic per round (S)]{{\begin{{tikzpicture}}
{axis % ('MB', '')}
\addplot[cBlue, mark=*, mark size=1.2pt] coordinates {{{coords(c, 3)}}};
\end{{axis}}\end{{tikzpicture}}}}\hfil
\subfloat[Memory above baseline (M)]{{\begin{{tikzpicture}}
{axis % ('MiB', ', legend pos=south east, legend style={draw=none, fill=none, font=\\tiny}')}
\addplot[cBlue, mark=*, mark size=1.2pt] coordinates {{{coords(memline('certifier'), 4)}}};
\addlegendentry{{Certifier}}
\addplot[cOrange, dashed, mark=square*, mark size=1.2pt] coordinates {{{coords(memline('ag'), 4)}}};
\addlegendentry{{Aggregator}}
\end{{axis}}\end{{tikzpicture}}}}
\caption{{Scaling with $n$ ($L = 16$, $k = 0.2n$). (a, b) Medians, IQR within 2.9\% of the median; (c) exact sizes; (d) one measurement per $n$.
All values are observed; no projected round times are shown. (a)~One certifier's GoodTrans and BLS share.
(b)~CertCombine. (c)~Transcripts sent by the aggregator to the $k+1$ certifiers. (d)~Input held plus peak working
memory of a certifier (during GoodTrans) and of the aggregator (during Build and CertCombine).}}
\label{{fig:scaling}}
\end{{figure}}
"""
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, 'fig_scaling.tex'), 'w') as f:
        f.write(tex)
    print("wrote", os.path.join(OUT, 'fig_scaling.tex'))


if __name__ == '__main__':
    main()