"""Robust certification under audit evasion (a bounded, worst-case adversary -- no attack is simulated).

If a truly missed compromise can appear benign to an audit with probability up to eta, a robust upper bound on
the miss rate is U/(1-eta), and the recall floor becomes TP_lo/(TP_lo + FN_up/(1-eta)). This degrades the
certificate gracefully and keeps it valid under eta-bounded evasion. We sweep eta and show the floor stays a
valid lower bound (coverage against the true recall) while shrinking predictably.
Writes results/robust.json, results/robust.md, results/robust.png.
"""
from __future__ import annotations

import json
import os

import numpy as np

from .accept import Cfg, simulate, estimates
from .data import DATASET_TITLE

CELLS = [("unsw_std", "reconnaissance"), ("cic2017", "dos"), ("unsw_std", "generic"), ("cic2017", "web")]
ETAS = [0.0, 0.05, 0.1, 0.2, 0.3]
SEEDS = list(range(8))
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
ALPHA = 0.05


def run():
    os.makedirs(OUT, exist_ok=True)
    cells = []
    for ds, fam in CELLS:
        runs = [simulate(Cfg(dataset=ds, campaign=fam, audit_mode="stratified", pi_alert=1.0, audit_budget=20.0), s)
                for s in SEEDS]
        rec = float(np.mean([r.recall for r in runs]))
        pts = []
        for eta in ETAS:
            es = [estimates(r, eta=eta) for r in runs]
            rlo = [e["recall_lower_robust"] for e in es]
            cov = np.mean([e["recall_lower_robust"] <= e["recall"] + 1e-9 for e in es])
            mcov = np.mean([e["ace_upper_robust"] >= e["mu_true"] for e in es])
            pts.append(dict(eta=eta, recall_lo=float(np.median(rlo)), recall_cov=float(cov), mu_cov=float(mcov)))
        cells.append(dict(dataset=ds, campaign=fam, title=DATASET_TITLE[ds], recall=rec, pts=pts))
        print(f"{DATASET_TITLE[ds][:16]:16s}/{fam:13s} R={rec:.2f}  " +
              "  ".join(f"eta{p['eta']}->floor{p['recall_lo']:.2f}(cov{p['recall_cov']:.2f})" for p in pts))
    json.dump(dict(cells=cells, etas=ETAS, seeds=len(SEEDS)), open(os.path.join(OUT, "robust.json"), "w"), indent=1)
    _report(cells)
    _plot(cells)
    return cells


def _report(cells):
    rc = [p["recall_cov"] for c in cells for p in c["pts"]]
    mc = [p["mu_cov"] for c in cells for p in c["pts"]]
    L = ["# Robust certification under audit evasion (eta)", "",
         f"{len(SEEDS)} seeds, alpha={ALPHA}, stratified auditing. eta = worst-case probability that a truly missed "
         "compromise evades an audit (appears benign). This is a bounded adversary bound, not a simulated attack.", "",
         "| Dataset | Family | Recall | floor @eta=0 | @0.1 | @0.2 | @0.3 |",
         "|---|---|---|---|---|---|---|"]
    for c in cells:
        g = {p["eta"]: p["recall_lo"] for p in c["pts"]}
        L.append(f"| {c['title']} | {c['campaign']} | {c['recall']:.2f} | {g[0.0]:.2f} | {g[0.1]:.2f} | "
                 f"{g[0.2]:.2f} | {g[0.3]:.2f} |")
    L += ["",
          f"- The robust recall floor stays a valid lower bound at every eta (coverage min {min(rc):.2f}), and the "
          f"robust miss-rate upper bound stays valid too (coverage min {min(mc):.2f}); targets $\\ge{1-ALPHA:.2f}$.",
          "- The floor degrades smoothly with eta (roughly by the factor $1-\\eta$ through the FN term), so a "
          "deployment can state what its certificate guarantees even if audits are imperfectly evasion-resistant.",
          "- This reclaims a defensive-robustness guarantee without modelling any specific attack: the certificate "
          "holds for the worst case within the eta budget."]
    open(os.path.join(OUT, "robust.md"), "w", encoding="utf-8").write("\n".join(L))
    print("\nreport:", os.path.join(OUT, "robust.md"))


def _plot(cells):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:
        print("(plot skipped:", e, ")"); return
    fig, ax = plt.subplots(figsize=(6, 4.2))
    for c in sorted(cells, key=lambda z: -z["recall"]):
        ax.plot(ETAS, [p["recall_lo"] for p in c["pts"]], "o-",
                label=f"{c['title'].split()[0]}/{c['campaign'][:5]} (R={c['recall']:.2f})")
        ax.axhline(c["recall"], ls=":", lw=0.7, c=ax.lines[-1].get_color())
    ax.set_xlabel("audit-evasion budget $\\eta$"); ax.set_ylabel("robust certified recall floor")
    ax.set_title("Certificate degrades gracefully under bounded audit evasion\n(dotted = true recall)")
    ax.legend(fontsize=7); ax.set_ylim(0, 1)
    fig.tight_layout()
    p = os.path.join(OUT, "robust.png"); fig.savefig(p, dpi=130); plt.close(fig)
    print("figure:", p)


if __name__ == "__main__":
    run()
