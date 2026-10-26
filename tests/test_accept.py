"""Sanity checks for the acceptance simulator and estimators (pom.accept).

Run:  python -m tests.test_accept
- ACE point estimate is ~unbiased for the true miss rate; the ACE upper bound covers it.
- naive underestimates the miss rate; IPCW with the true delay model is much closer.
- Coverage of the ACE upper bound across seeds is >= 1 - alpha.
"""
import numpy as np

from pom.accept import Cfg, simulate, estimates


def test_unbiased_and_cover():
    cfg = Cfg(H=800, days=14, audit_budget=20.0, prevalence=0.012)
    mus, naive, ipcw, ipcw0, ace_pt, cover, within = [], [], [], [], [], 0, 0
    for s in range(20):
        r = simulate(cfg, s)
        e = estimates(r)
        mus.append(e["mu_true"]); naive.append(e["naive"]); ipcw.append(e["ipcw"])
        ipcw0.append(e["ipcw0"]); ace_pt.append(e["ace_point"])
        cover += e["ace_upper"] >= e["mu_true"]
        within += e["ace_upper"] <= 2.0 * e["mu_true"]
    mu = np.mean(mus)
    print(f"mu_true={mu:.5f}  naive={np.mean(naive):.5f}  ipcw0(assume full disc)={np.mean(ipcw0):.5f}  "
          f"ipcw(oracle p_never)={np.mean(ipcw):.5f}  ace_pt={np.nanmean(ace_pt):.5f}")
    print(f"ACE upper covers mu in {cover}/20 seeds; within 2x in {within}/20")
    # naive and the realistic IPCW (which cannot know the never-discovered share) both read low:
    assert np.mean(naive) < 0.95 * mu, "naive should underestimate"
    assert np.nanmean(ipcw0) < 0.95 * mu, "IPCW assuming full discovery should underestimate (never-discovered mass)"
    # the audit-based estimate needs neither a delay model nor p_never:
    assert abs(np.nanmean(ace_pt) - mu) < 0.25 * mu, "ACE point estimate should be ~unbiased"
    assert cover >= 19, "ACE upper bound should cover (alpha=0.05)"


if __name__ == "__main__":
    test_unbiased_and_cover()
    print("OK")
