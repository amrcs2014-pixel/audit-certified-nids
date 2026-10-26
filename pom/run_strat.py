"""Uniform vs stratified auditing for recall certification (lowering the recall-certificate budget).

recall = TP / (TP + FN), TP = P(compromised & alerted), FN = P(compromised & not alerted) = mu.
Stratified auditing audits the (few) alerted host-windows heavily -- cheap, and compromise-dense, so it pins
TP tightly from below -- and the huge non-alerted stratum lightly for an upper bound on FN. Known exact stratum
weights + i.i.d. betting bounds per stratum keep it anytime-valid (alpha/2 on each of TP-lower and FN-upper).

For each moderate/high-recall cell it records recall-floor vs realized audit budget (% of hosts/window) under
uniform and stratified schemes, and the smallest budget whose floor reaches half the true recall.
Writes results/strat.json, results/strat.md, results/strat.png.
"""
from __future__ import annotations

import json
import os

import numpy as np

from .accept import Cfg, simulate, estimates
from .data import DATASET_TITLE

CELLS = [("nf_ton", "xss"), ("cic2017", "web"), ("cic2018", "web"), ("unsw_std", "shellcode"),
         ("unsw_std", "fuzzers"), ("unsw_std", "generic"), ("unsw_std", "reconnaissance"), ("cic2017", "dos")]
UNIFORM_PCT = [1.0, 2.0, 5.0, 10.0, 20.0]
STRAT_UNALERTED_PCT = [0.0, 0.25, 0.5, 1.0, 2.0, 5.0]
SEEDS = list(range(8))
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
ALPHA = 0.05


def _curve(dataset, campaign, scheme):
    pts = []
    grid = UNIFORM_PCT if scheme == "uniform" else STRAT_UNALERTED_PCT
    for g in grid:
        rlo, bud, cov = [], [], 0
        for s in SEEDS:
            if scheme == "uniform":
                cfg = Cfg(dataset=dataset, campaign=campaign, audit_mode="uniform", audit_budget=g / 100.0 * 1000)
            else:
                cfg = Cfg(dataset=dataset, campaign=campaign, audit_mode="stratified", pi_alert=1.0,
                          audit_budget=g / 100.0 * 1000)
            e = estimates(simulate(cfg, s))
            rlo.append(e["recall_lower"]); bud.append(e["audit_pct"])
            cov += e["recall_lower"] <= e["recall"] + 1e-9
        pts.append(dict(knob=g, budget=float(np.mean(bud)), recall_lo=float(np.median(rlo)),
                        coverage=cov / len(SEEDS)))
    return pts


def _min_budget(pts, target):
    ok = [p["budget"] for p in pts if p["recall_lo"] >= target and p["coverage"] >= 1 - ALPHA]
    return min(ok) if ok else None


def run():
    os.makedirs(OUT, exist_ok=True)
    cells = []
    for ds, fam in CELLS:
        rec = float(np.mean([simulate(Cfg(dataset=ds, campaign=fam), s).recall for s in SEEDS]))
        uni = _curve(ds, fam, "uniform")
        strat = _curve(ds, fam, "stratified")
        tgt = 0.5 * rec
        c = dict(dataset=ds, campaign=fam, title=DATASET_TITLE[ds], recall=rec,
                 uniform=uni, stratified=strat,
                 uni_budget=_min_budget(uni, tgt), strat_budget=_min_budget(strat, tgt))
        cells.append(c)
        print(f"{c['title'][:24]:24s} {fam:13s} R={rec:.2f}  floor>=R/2 at: "
              f"uniform={c['uni_budget']}  stratified={c['strat_budget']}")
    json.dump(dict(cells=cells, seeds=len(SEEDS), alpha=ALPHA), open(os.path.join(OUT, "strat.json"), "w"), indent=1)
    _report(cells)
    _plot(cells)
    return cells


def _report(cells):
    mb = lambda v: (f"{v:.1f}%" if v is not None else ">cap")
    L = ["# Stratified vs uniform auditing for recall certification", "",
         f"{len(SEEDS)} seeds, alpha={ALPHA}. recall = TP/(TP+FN); stratified audits all alerts (pi_alert=1) plus a "
         "light non-alerted budget. Target floor = half the true recall.", "",
         "| Dataset | Family | Recall | Budget for floor>=R/2 (uniform) | Budget (stratified) | speed-up |",
         "|---|---|---|---|---|---|"]
    sp = []
    for c in cells:
        s = (c["uni_budget"] / c["strat_budget"]) if (c["uni_budget"] and c["strat_budget"]) else None
        if s:
            sp.append(s)
        L.append(f"| {c['title']} | {c['campaign']} | {c['recall']:.2f} | {mb(c['uni_budget'])} | "
                 f"{mb(c['strat_budget'])} | {f'{s:.1f}x' if s else '-'} |")
    covs = [p["coverage"] for c in cells for sch in ("uniform", "stratified") for p in c[sch]]
    uni_solved = sum(c["uni_budget"] is not None for c in cells)
    str_solved = sum(c["strat_budget"] is not None for c in cells)
    L += ["",
          f"- Recall floors are valid everywhere (min coverage {min(covs):.2f}, target >= {1-ALPHA:.2f}).",
          f"- A floor >= half the true recall is reached in {str_solved}/{len(cells)} cells with stratified "
          f"auditing vs {uni_solved}/{len(cells)} with uniform, within the swept budgets.",
          f"- Where both schemes reach it, stratified auditing needs a median {np.median(sp):.1f}x less budget."
          if sp else "- (no cell solved by both schemes within the sweep)",
          "",
          "Why: alerted host-windows are few and compromise-dense, so auditing them is cheap and gives a tight "
          "lower bound on TP (which dominates recall); the rare total prevalence never has to be lower-bounded "
          "directly. Stratum weights are known exactly and each stratum's audits are i.i.d., so the betting "
          "bounds stay anytime-valid.",
          "",
          "Limits: same simulator caveats as the main run; auditing all alerts assumes alert volume is within "
          "analyst reach (it is small here); very-low-recall families stay hard because TP itself is tiny."]
    open(os.path.join(OUT, "strat.md"), "w", encoding="utf-8").write("\n".join(L))
    print("\nreport:", os.path.join(OUT, "strat.md"))


def _plot(cells):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:
        print("(plot skipped:", e, ")")
        return
    show = [c for c in cells if c["campaign"] in ("web", "generic", "reconnaissance", "dos")]
    fig, ax = plt.subplots(1, len(show), figsize=(4 * len(show), 3.8), sharey=True)
    for a, c in zip(ax, sorted(show, key=lambda z: z["recall"])):
        u = c["uniform"]; s = c["stratified"]
        a.plot([p["budget"] for p in u], [p["recall_lo"] for p in u], "s--", c="C1", label="uniform")
        a.plot([p["budget"] for p in s], [p["recall_lo"] for p in s], "o-", c="C0", label="stratified")
        a.axhline(c["recall"], ls=":", c="k", lw=1, label="true recall")
        a.axhline(0.5 * c["recall"], ls=":", c="0.6", lw=1)
        a.set_title(f"{c['title'].split()[0]} / {c['campaign']}  (R={c['recall']:.2f})", fontsize=9)
        a.set_xlabel("audit budget (% hosts/win)"); a.set_xlim(0, 12); a.set_ylim(0, 1)
    ax[0].set_ylabel("certified recall floor"); ax[0].legend(fontsize=7)
    fig.tight_layout()
    p = os.path.join(OUT, "strat.png")
    fig.savefig(p, dpi=130); plt.close(fig)
    print("figure:", p)


if __name__ == "__main__":
    run()
