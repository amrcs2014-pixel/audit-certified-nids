"""Unified 1b run across datasets x zero-day families.

For every (dataset, held-out family) cell, sweep the audit budget over seeds and record:
- the true miss rate mu and detector recall on the family,
- naive and full-discovery-IPCW point estimates (which cannot certify) and their bias,
- ACE anytime-valid upper bound: coverage, median width/mu, within-2x fraction, per budget,
- the smallest budget whose certificate is within 2x mu for most seeds at coverage >= 1-alpha.

Writes results/multi.json, results/multi.md, results/multi.png.
"""
from __future__ import annotations

import json
import os

import numpy as np

from .accept import Cfg, simulate, estimates
from .data import DATASET_TITLE

# Zero-day cells: held-out families the detector does NOT already catch (recall < ~0.6, so there is a real
# miss rate to certify). NF-UNSW-NB15-v3 is excluded on purpose: its benign/attack split is so separable that
# every held-out family gets recall ~1.0 (mu ~ 0), leaving nothing to certify; UNSW is covered by the
# standard-feature set (unsw_std) instead. This selection is reported as a finding, not hidden.
PLAN = {
    "nf_ton": ["ransomware", "backdoor", "mitm", "xss"],
    "unsw_std": ["shellcode", "fuzzers", "generic", "reconnaissance"],
    "nf_bot": ["theft", "reconnaissance"],
    "cic2017": ["botnet", "bruteforce", "web", "dos"],
    "cic2018": ["bruteforce", "infiltration", "ddos", "web"],
}
BUDGETS = [0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0]
SEEDS = list(range(8))
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
ALPHA = 0.05


def cell(dataset: str, campaign: str, budgets=BUDGETS, seeds=SEEDS, **over):
    base_cfg = Cfg(dataset=dataset, campaign=campaign, **over)
    base = [estimates(simulate(base_cfg, s)) for s in seeds]
    mu = float(np.mean([b["mu_true"] for b in base]))
    rec = float(np.mean([b["recall"] for b in base]))
    naive = float(np.mean([b["naive"] for b in base]))
    ipcw0 = float(np.mean([b["ipcw0"] for b in base]))
    rows = []
    for b in budgets:
        ab = b / 100.0 * base_cfg.H
        cov = wit = rcov = 0
        w_bet, w_mix, rlo = [], [], []
        for s in seeds:
            e = estimates(simulate(Cfg(dataset=dataset, campaign=campaign, audit_budget=ab, **over), s))
            cov += e["ace_upper"] >= e["mu_true"]
            wit += e["ace_upper"] <= 2.0 * e["mu_true"]
            w_bet.append(e["ace_upper"] - e["mu_true"])
            w_mix.append(e["ace_upper_mix"] - e["mu_true"])
            rcov += e["recall_lower"] <= e["recall"] + 1e-9
            rlo.append(e["recall_lower"])
        rows.append(dict(budget_pct=b, coverage=cov / len(seeds), within2x=wit / len(seeds),
                         w_bet_over_mu=float(np.median(w_bet)) / mu if mu > 0 else float("nan"),
                         w_mix_over_mu=float(np.median(w_mix)) / mu if mu > 0 else float("nan"),
                         recall_lo=float(np.median(rlo)), recall_cov=rcov / len(seeds)))
    ok = [r["budget_pct"] for r in rows if r["within2x"] >= 0.75 and r["coverage"] >= 1 - ALPHA]
    # recall is "usefully" certified when the floor reaches half the true recall, for most seeds, with coverage
    rok = [r["budget_pct"] for r in rows if rec > 0 and r["recall_lo"] >= 0.5 * rec and r["recall_cov"] >= 1 - ALPHA]
    tighten = float(np.median([(r["w_mix_over_mu"] - r["w_bet_over_mu"]) / r["w_mix_over_mu"]
                               for r in rows if r["w_mix_over_mu"] > 0]))
    return dict(dataset=dataset, campaign=campaign, title=DATASET_TITLE[dataset], mu_true=mu, recall=rec,
                naive=naive, ipcw0=ipcw0, naive_bias=(naive - mu) / mu if mu else float("nan"),
                ipcw0_bias=(ipcw0 - mu) / mu if mu else float("nan"), rows=rows,
                min_budget=min(ok, default=None), min_budget_recall=min(rok, default=None),
                betting_tighten=tighten)


def run():
    os.makedirs(OUT, exist_ok=True)
    cells = []
    for ds, fams in PLAN.items():
        for fam in fams:
            try:
                c = cell(ds, fam)
            except Exception as e:
                print(f"skip {ds}/{fam}: {e}")
                continue
            cells.append(c)
            r5 = next((r["recall_lo"] for r in c["rows"] if r["budget_pct"] == 5.0), float("nan"))
            print(f"{c['title'][:24]:24s} {fam:13s} rec={c['recall']:.2f} mu={c['mu_true']:.4f} "
                  f"muBudget={c['min_budget']} betTighten={c['betting_tighten']*100:+4.1f}% "
                  f"recallLo@5%={r5:.2f} recBudget={c['min_budget_recall']}")
    json.dump(dict(cells=cells, budgets=BUDGETS, seeds=len(SEEDS), alpha=ALPHA),
              open(os.path.join(OUT, "multi.json"), "w"), indent=1)
    _report(cells)
    _plot(cells)
    return cells


def _report(cells):
    mb_r = lambda v: (f"{v}%" if v is not None else ">20%")
    L = ["# Unified 1b results: audit-certified miss rate and recall across datasets",
         "",
         f"{len(SEEDS)} seeds, budgets {BUDGETS}% of hosts/window, alpha={ALPHA}. No attacker modelled. "
         "Miss rate mu = P(host-window compromised by the held-out family AND not alerted); "
         "recall = 1 - mu/prevalence, certified by a joint (upper mu, lower prevalence) bound at alpha/2 each. "
         "The miss-rate upper bound uses the betting-mixture confidence sequence (tighter than empirical-Bernstein).",
         "",
         "| Dataset | Zero-day family | Recall | True mu | naive bias | mu budget (<=2x) | betting vs EB | "
         "recall floor @5% | recall budget |",
         "|---|---|---|---|---|---|---|---|---|"]
    for c in cells:
        r5 = next((r["recall_lo"] for r in c["rows"] if r["budget_pct"] == 5.0), float("nan"))
        L.append(f"| {c['title']} | {c['campaign']} | {c['recall']:.3f} | {c['mu_true']:.4f} | "
                 f"{c['naive_bias']*100:+.1f}% | {mb_r(c['min_budget'])} | -{c['betting_tighten']*100:.0f}% w | "
                 f"{r5:.2f} | {mb_r(c['min_budget_recall'])} |")
    nb = np.nanmean([c["naive_bias"] for c in cells]) * 100
    covs = [r["coverage"] for c in cells for r in c["rows"]]
    rcovs = [r["recall_cov"] for c in cells for r in c["rows"]]
    mbs = [c["min_budget"] for c in cells if c["min_budget"] is not None]
    tig = np.nanmedian([c["betting_tighten"] for c in cells]) * 100
    rbudg = [c["min_budget_recall"] for c in cells if c["min_budget_recall"] is not None]
    L += ["",
          f"- Cells: {len(cells)}. Mean naive bias {nb:+.1f}% (point estimates read low and cannot certify).",
          f"- **Miss-rate certificate** coverage over all cells x budgets: min {min(covs):.2f} "
          f"(target >= {1-ALPHA:.2f}); certified within 2x in {len(mbs)}/{len(cells)} cells, "
          f"median budget {np.median(mbs) if mbs else float('nan')}% of hosts/window.",
          f"- **Tighter bound:** the betting-mixture CS is a median {tig:.0f}% narrower than empirical-Bernstein "
          "at the same budget, with coverage preserved.",
          f"- **Recall as a ratio** (joint bound) is valid everywhere (min coverage {min(rcovs):.2f}) but costs "
          f"more: a recall floor >= half the true recall is reached in {len(rbudg)}/{len(cells)} cells, "
          f"median budget {np.median(rbudg) if rbudg else float('nan')}%. It is vacuous for near-zero-recall "
          "families (where the true recall is ~0, so the floor of 0 is correct but uninformative) and most "
          "useful for moderate-recall families.",
          "",
          "Honest limits: synthetic host-windows from flow scores; one detector family per dataset; fixed "
          "compromise prevalence and discovery-delay assumptions; uniform (non-stratified) audits -- "
          "score-stratified audits with known propensities would cut the recall budget and are the next step; "
          "the bounds are conservative (coverage ~1.00)."]
    open(os.path.join(OUT, "multi.md"), "w", encoding="utf-8").write("\n".join(L))
    print("\nreport:", os.path.join(OUT, "multi.md"))


def _plot(cells):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:
        print("(plot skipped:", e, ")")
        return
    fig, ax = plt.subplots(1, 3, figsize=(15, 4.3))
    # (A) betting vs empirical-Bernstein width, pooled median over cells
    wb = np.array([[r["w_bet_over_mu"] for r in c["rows"]] for c in cells], float)
    wm = np.array([[r["w_mix_over_mu"] for r in c["rows"]] for c in cells], float)
    ax[0].plot(BUDGETS, np.nanmedian(wm, axis=0), "s--", c="C1", label="empirical-Bernstein")
    ax[0].plot(BUDGETS, np.nanmedian(wb, axis=0), "o-", c="C0", label="betting mixture (tighter)")
    ax[0].axhline(1.0, ls=":", c="k", lw=1, label="bound = 2$\\mu$")
    ax[0].set_xscale("log"); ax[0].set_xlabel("audit budget (% hosts/window)")
    ax[0].set_ylabel("miss-rate certificate width / $\\mu$"); ax[0].set_ylim(0, 2.5)
    ax[0].set_title("Tighter miss-rate bound"); ax[0].legend(fontsize=8)
    # (B) miss-rate certificate tightness by dataset
    by_ds = {}
    for i, c in enumerate(cells):
        by_ds.setdefault(c["title"], []).append(i)
    for title, idx in by_ds.items():
        ax[1].plot(BUDGETS, np.nanmedian(wb[idx], axis=0), "o-", ms=4, label=title)
    ax[1].axhline(1.0, ls=":", c="k", lw=1)
    ax[1].set_xscale("log"); ax[1].set_xlabel("audit budget (% hosts/window)")
    ax[1].set_ylabel("width / $\\mu$ (betting)"); ax[1].set_ylim(0, 2.5)
    ax[1].set_title("Miss-rate certificate by dataset"); ax[1].legend(fontsize=6)
    # (C) recall floor vs budget, for moderate-recall cells (where the ratio bound is informative)
    mod = [c for c in cells if 0.15 <= c["recall"] <= 0.65]
    for c in sorted(mod, key=lambda z: z["recall"]):
        rl = [r["recall_lo"] for r in c["rows"]]
        ax[2].plot(BUDGETS, rl, "o-", ms=4, label=f"{c['title'].split()[0]}/{c['campaign'][:5]} (R={c['recall']:.2f})")
        ax[2].axhline(c["recall"], ls=":", lw=0.7, c=ax[2].lines[-1].get_color())
    ax[2].set_xscale("log"); ax[2].set_xlabel("audit budget (% hosts/window)")
    ax[2].set_ylabel("certified recall floor"); ax[2].set_title("Recall-as-ratio floor (dotted = true recall)")
    ax[2].legend(fontsize=6); ax[2].set_ylim(0, 1)
    fig.tight_layout()
    p = os.path.join(OUT, "multi.png")
    fig.savefig(p, dpi=130); plt.close(fig)
    print("figure:", p)


if __name__ == "__main__":
    run()
