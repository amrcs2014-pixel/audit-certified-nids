"""Coverage and tightness of the predictable-betting CS vs the fixed-grid empirical-Bernstein bound.

Run:  python -m tests.test_betting
On i.i.d. Bernoulli(theta) streams (the regime of the audited subsample):
- both bounds cover (miscoverage <= alpha), and
- the betting upper bound is tighter (smaller width) than the mixture, especially for rare theta.
Also checks the two-sided (upper, lower) bracket covers theta jointly at alpha/2 each.
"""
import numpy as np

from pom.cs import upper_at, upper_betting, lower_betting

ALPHA = 0.05


def cover_width(theta, n, reps=2000, seed=0):
    rng = np.random.default_rng(seed)
    mis_bet = mis_mix = 0
    w_bet, w_mix = [], []
    for _ in range(reps):
        x = (rng.random(n) < theta).astype(float)
        ub = upper_betting(x, ALPHA)
        um = float(upper_at(x, [n], ALPHA)[0])
        mis_bet += ub < theta
        mis_mix += um < theta
        w_bet.append(ub - theta); w_mix.append(um - theta)
    return (mis_bet / reps, np.median(w_bet)), (mis_mix / reps, np.median(w_mix))


def joint_bracket(theta, n, reps=2000, seed=1):
    rng = np.random.default_rng(seed)
    miss = 0
    for _ in range(reps):
        x = (rng.random(n) < theta).astype(float)
        U = upper_betting(x, ALPHA / 2)
        L = lower_betting(x, ALPHA / 2)
        miss += not (L <= theta <= U)
    return miss / reps


if __name__ == "__main__":
    print(f"{'theta':>7} {'n':>6} | {'bet miscov':>10} {'bet width':>10} | {'mix miscov':>10} {'mix width':>10}")
    for theta, n in [(0.01, 2500), (0.05, 2500), (0.2, 1000), (0.01, 500)]:
        (mb, wb), (mm, wm) = cover_width(theta, n)
        print(f"{theta:>7} {n:>6} | {mb:>10.3f} {wb:>10.5f} | {mm:>10.3f} {wm:>10.5f}")
        assert mb <= ALPHA + 0.015, f"betting under-covers at theta={theta}"
        assert mm <= ALPHA + 0.015, f"mixture under-covers at theta={theta}"
        assert wb <= wm + 1e-9, f"betting should be <= mixture width at theta={theta}"
    j = joint_bracket(0.05, 2000)
    print(f"\njoint (upper,lower) bracket miscoverage at alpha/2 each: {j:.3f} (target <= {ALPHA})")
    assert j <= ALPHA + 0.01
    print("OK")
