"""Coverage checks for the anytime-valid upper bound (pom.cs).

Run:  python -m tests.test_cs
Checks time-uniform coverage (bound holds at every checked prefix) for
  (1) i.i.d. Bernoulli with a rare mean,
  (2) a non-stationary sequence (time-varying conditional means),
  (3) the audit form X = A * R with A ~ Bernoulli(pi) independent of R,
and that the bound shrinks with n.
"""
import numpy as np

from pom.cs import upper_at

ALPHA = 0.05


def coverage(make, reps=1000, n=20000, checks=60, seed=0):
    rng = np.random.default_rng(seed)
    ns = np.unique(np.linspace(50, n, checks).astype(int))
    fails = 0
    widths = []
    for _ in range(reps):
        x, mu = make(rng, n)
        cm = np.cumsum(mu)[ns - 1] / ns
        U = upper_at(x, ns, ALPHA)
        fails += np.any(cm > U)
        widths.append(U[-1] - cm[-1])
    return fails / reps, float(np.median(widths))


def iid_rare(rng, n):
    p = 0.003
    return (rng.random(n) < p).astype(float), np.full(n, p)


def nonstationary(rng, n):
    t = np.arange(n)
    mu = 0.002 + 0.01 * (t > n // 2) + 0.005 * np.sin(t / 700.0) ** 2
    return (rng.random(n) < mu).astype(float), mu


def audit_form(rng, n):
    pi = 0.05
    r = (rng.random(n) < 0.04).astype(float)    # unknown missed indicators
    a = (rng.random(n) < pi).astype(float)       # secret audit coin
    return a * r, pi * r                          # E[X | R] = pi * R


if __name__ == "__main__":
    for name, mk in [("iid rare p=0.003", iid_rare), ("non-stationary", nonstationary), ("audit form", audit_form)]:
        miss, w = coverage(mk)
        print(f"{name:20s} time-uniform miscoverage {miss:.3f} (alpha={ALPHA})  median final width {w:.5f}")
        assert miss <= ALPHA + 0.02, f"coverage failed for {name}"
    rng = np.random.default_rng(1)
    x = (rng.random(200000) < 0.01).astype(float)
    U = upper_at(x, [1000, 10000, 100000, 200000], ALPHA)
    print("bound shrinks with n:", np.round(U, 5))
    assert np.all(np.diff(U) < 0)
    print("OK")
