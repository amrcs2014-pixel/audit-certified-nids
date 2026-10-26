"""Pilot run for idea 1b: how many random audits certify the miss rate on a new network?

Sweeps the audit budget (audits per window, as a % of hosts) over seeds, and reports for each budget:
- coverage of the ACE anytime-valid upper bound (target >= 1 - alpha),
- median certificate width (upper bound minus true mu), absolute and as a multiple of mu,
- fraction of seeds whose certificate is within 2x the true mu.

It also records naive and IPCW point estimates (which need a delay model and the unknowable never-discovered
share), to show they cannot certify. Writes results/run1b.json and results/run1b.png.

Success criterion for this pilot (defensive analogue of the kill criteria):
  the smallest budget at which the ACE upper bound is within 2x the true mu for >= 8/10 seeds,
  at coverage >= 1 - alpha.
"""
from __future__ import annotations

import json
import os

import numpy as np

from .accept import Cfg, simulate, estimates

BUDGETS_PCT = [0.25, 0.5, 1.0, 2.0, 5.0]
SEEDS = list(range(10))
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")


def run(cfg0: Cfg = Cfg(), budgets=BUDGETS_PCT, seeds=SEEDS):
    os.makedirs(OUT, exist_ok=True)
    rows = []
    # reference: true mu, recall and the (uncertifiable) point estimators, from a no-audit run per seed
    base = [estimates(simulate(Cfg(**{**cfg0.__dict__, "audit_budget": 0.0}), s)) for s in seeds]
    mu_true = float(np.mean([b["mu_true"] for b in base]))
    recall = float(np.mean([b["recall"] for b in base]))
    naive = float(np.mean([b["naive"] for b in base]))
    ipcw0 = float(np.mean([b["ipcw0"] for b in base]))
    ipcw = float(np.mean([b["ipcw"] for b in base]))
    print(f"campaign={cfg0.campaign}  true miss-rate mu={mu_true:.5f}  (recall={recall:.3f})")
    print(f"point estimates that CANNOT certify:  naive={naive:.5f}  "
          f"IPCW[assume full discovery]={ipcw0:.5f}  IPCW[oracle p_never]={ipcw:.5f}\n")
    print(f"{'budget':>8} {'aud/win':>8} {'cover':>6} {'E[aud miss]':>11} {'med width':>10} "
          f"{'width/mu':>9} {'<=2x mu':>8}")
    for b in budgets:
        ab = b / 100.0 * cfg0.H
        cov = wit = 0
        widths, nam = [], []
        for s in seeds:
            e = estimates(simulate(Cfg(**{**cfg0.__dict__, "audit_budget": ab}), s))
            U, mu = e["ace_upper"], e["mu_true"]
            cov += U >= mu
            wit += U <= 2.0 * mu
            widths.append(U - mu)
            nam.append(e["n_audit_missed"])
        mw = float(np.median(widths))
        rows.append(dict(budget_pct=b, audits_per_win=ab, coverage=cov / len(seeds),
                         exp_audit_missed=float(np.mean(nam)), med_width=mw,
                         med_width_over_mu=mw / mu_true, within2x=wit / len(seeds)))
        print(f"{b:>7.2f}% {ab:>8.1f} {cov/len(seeds):>6.2f} {np.mean(nam):>11.1f} "
              f"{mw:>10.5f} {mw/mu_true:>9.2f} {wit/len(seeds):>8.1f}")

    ok = [r for r in rows if r["within2x"] >= 0.8 and r["coverage"] >= 1 - cfg0.alpha]
    min_budget = min((r["budget_pct"] for r in ok), default=None)
    out = dict(cfg=cfg0.__dict__, mu_true=mu_true, recall=recall,
               naive=naive, ipcw0=ipcw0, ipcw=ipcw, rows=rows,
               min_budget_pct_within2x=min_budget)
    json.dump(out, open(os.path.join(OUT, "run1b.json"), "w"), indent=1)
    print(f"\nSmallest budget meeting the pilot criterion (<=2x mu for >=8/10 seeds, coverage>=0.95): "
          f"{min_budget}% of hosts/window" if min_budget else
          "\nNo swept budget met the pilot criterion.")
    _plot(out)
    return out


def _plot(out):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:
        print("(plot skipped:", e, ")")
        return
    r = out["rows"]
    b = [x["budget_pct"] for x in r]
    mu = out["mu_true"]
    fig, ax = plt.subplots(1, 2, figsize=(10, 4))
    ax[0].axhline(mu, ls="--", c="k", lw=1, label="true miss-rate $\\mu$")
    ax[0].axhline(out["naive"], ls=":", c="C3", lw=1, label="naive (cannot certify)")
    ax[0].axhline(out["ipcw0"], ls=":", c="C1", lw=1, label="IPCW, full-discovery (cannot certify)")
    ax[0].plot(b, [x["med_width"] + mu for x in r], "o-", c="C0", label="ACE upper bound (median)")
    ax[0].set_xlabel("audit budget (% of hosts / window)"); ax[0].set_ylabel("miss-rate estimate")
    ax[0].set_title("Certified upper bound vs budget"); ax[0].legend(fontsize=7); ax[0].set_ylim(0)
    ax[1].plot(b, [x["med_width_over_mu"] for x in r], "o-", c="C0")
    ax[1].axhline(1.0, ls="--", c="k", lw=1, label="width = $\\mu$ (bound = $2\\mu$)")
    ax[1].set_xlabel("audit budget (% of hosts / window)"); ax[1].set_ylabel("certificate width / $\\mu$")
    ax[1].set_title("Tightness vs budget"); ax[1].legend(fontsize=7)
    fig.tight_layout()
    p = os.path.join(OUT, "run1b.png")
    fig.savefig(p, dpi=130); plt.close(fig)
    print("figure:", p)


if __name__ == "__main__":
    run()
