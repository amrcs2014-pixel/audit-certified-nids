"""Anytime-valid upper confidence bound for the running average of conditional means.

Setting: X_1, X_2, ... in [0, 1] arrive in order, with E[X_i | past] >= mu_i. We want U_n such that
    P( for all n:  (1/n) * sum_{i<=n} mu_i  <=  U_n ) >= 1 - alpha.

Construction: the empirical-Bernstein supermartingale of Waudby-Smith & Ramdas (JRSSB 2024, Thm 2), applied to
1 - X for the upper tail, with a *constant* lambda so that it covers the plain (unweighted) average of the
conditional means. A uniform mixture over a lambda grid keeps it tight across sample sizes. For each lambda,
    M_n(lambda) = exp( lambda * (n * mubar - S_n) - psi_E(lambda) * V_n ),
where S_n = sum X_i, V_n = sum 4 (X_i - muhat_{i-1})^2 with predictable muhat_{i-1} = (1/2 + sum_{j<i} X_j) / i,
and psi_E(l) = (-log(1 - l) - l) / 4. The mixture is a nonnegative supermartingale when mubar is the true
average, so by Ville's inequality U_n = sup{ mubar : mean_k M_n(lambda_k) < 1/alpha }.
If E[X_i | past] is larger than mu_i, the supermartingale property still holds (conservative case).
"""
from __future__ import annotations

import numpy as np

LAMS = np.geomspace(1e-4, 0.8, 48)


def psi_e(lam):
    return (-np.log1p(-lam) - lam) / 4.0


PSI = psi_e(LAMS)


def prefix_stats(x: np.ndarray):
    """Cumulative S_n and V_n for every prefix n = 1..len(x)."""
    x = np.asarray(x, dtype=np.float64)
    n = len(x)
    if n == 0:
        return np.zeros(0), np.zeros(0)
    cs = np.cumsum(x)
    i = np.arange(1, n + 1, dtype=np.float64)
    prev = np.concatenate(([0.0], cs[:-1]))
    muhat_prev = (0.5 + prev) / i
    v = 4.0 * (x - muhat_prev) ** 2
    return cs, np.cumsum(v)


def eb_upper(S, V, n, alpha: float, iters: int = 60):
    """Vectorised upper bound for arrays of (S_n, V_n, n). Returns U in [S/n, 1] (1.0 when n == 0)."""
    S = np.atleast_1d(np.asarray(S, dtype=np.float64))
    V = np.atleast_1d(np.asarray(V, dtype=np.float64))
    n = np.atleast_1d(np.asarray(n, dtype=np.float64))
    out = np.ones_like(S)
    ok = n > 0
    if not ok.any():
        return out
    S, V, n = S[ok], V[ok], n[ok]
    log_thr = np.log(1.0 / alpha)

    def g(mu):  # log of mixture value, shape (m,)
        a = LAMS[None, :] * (n[:, None] * mu[:, None] - S[:, None]) - PSI[None, :] * V[:, None]
        amax = a.max(axis=1)
        return amax + np.log(np.mean(np.exp(a - amax[:, None]), axis=1))

    lo = S / n
    hi = np.ones_like(lo)
    unbounded = g(hi) < log_thr          # even mu = 1 is not rejected
    for _ in range(iters):
        mid = 0.5 * (lo + hi)
        rej = g(mid) >= log_thr
        hi = np.where(rej, mid, hi)
        lo = np.where(rej, lo, mid)
    res = np.where(unbounded, 1.0, hi)
    out[ok] = res
    return out


def upper_at(x: np.ndarray, ns, alpha: float):
    """Upper bounds after the first ns[j] observations of the sequence x (fixed-grid empirical-Bernstein)."""
    S, V = prefix_stats(x)
    ns = np.asarray(ns, dtype=np.int64)
    Sj = np.where(ns > 0, S[np.maximum(ns - 1, 0)] if len(S) else 0.0, 0.0)
    Vj = np.where(ns > 0, V[np.maximum(ns - 1, 0)] if len(V) else 0.0, 0.0)
    return eb_upper(Sj, Vj, ns, alpha)


# ------------------------------------------------------------------ betting-mixture CS (tighter, 0/1 data)
# For i.i.d. Bernoulli X_1, X_2, ... (the audited miss / compromise indicators), and a grid of CONSTANT bets
# lambda_k, each capital process
#   M_n^k(m) = prod_{i<=n} (1 + lambda_k * s * (m - X_i)),      s = +1 upper, s = -1 lower
# is a nonnegative martingale (mean 1) under theta = m; their average K_n(m) = mean_k M_n^k(m) is too (method
# of mixtures / universal portfolio). By Ville, {m : K_n(m) < 1/alpha} is a confidence sequence. Because X is
# 0/1, the product depends only on the counts (n0 = #zeros, n1 = #ones):
#   log M_n^k(m) = n0 * log(1 + lambda_k s m) + n1 * log(1 + lambda_k s (m - 1)).
# So the bound is an exact function of (n0, n1, alpha) and solves in a few flops. The post-hoc best-lambda in the
# mixture makes it tighter than the fixed-grid empirical-Bernstein bound above, and it stays anytime-valid.
# Validity needs an i.i.d. conditional mean, which holds in the acceptance simulator (each host-window is
# compromised i.i.d. and missed i.i.d. given the family and detector).

LAM_BET = np.geomspace(1e-3, 0.9, 40)


def _betting_counts(n0: int, n1: int, alpha: float, upper: bool, iters: int = 64) -> float:
    n0, n1 = int(n0), int(n1)
    n = n0 + n1
    if n == 0:
        return 1.0 if upper else 0.0
    s = 1.0 if upper else -1.0
    thr = np.log(1.0 / alpha) + np.log(len(LAM_BET))   # mixture = mean_k -> logsumexp >= log(1/alpha)+log K
    xbar = n1 / n

    def lcap(m):                                       # log of the summed (un-normalised) mixture capital
        a = n0 * np.log1p(LAM_BET * s * m) + n1 * np.log1p(LAM_BET * s * (m - 1.0))
        amax = a.max()
        return amax + np.log(np.sum(np.exp(a - amax)))

    if upper:
        lo, hi = xbar, 1.0
        if lcap(hi) < thr:
            return 1.0
        for _ in range(iters):
            mid = 0.5 * (lo + hi)
            hi, lo = (mid, lo) if lcap(mid) >= thr else (hi, mid)
        return hi
    lo, hi = 0.0, xbar
    if lcap(lo) < thr:
        return 0.0
    for _ in range(iters):
        mid = 0.5 * (lo + hi)
        lo, hi = (mid, hi) if lcap(mid) >= thr else (lo, mid)
    return lo


def upper_betting(x: np.ndarray, alpha: float) -> float:
    """Tighter anytime-valid UPPER bound on the mean of an i.i.d. 0/1 sequence."""
    x = np.asarray(x)
    n1 = int(x.sum())
    return _betting_counts(len(x) - n1, n1, alpha, upper=True)


def lower_betting(x: np.ndarray, alpha: float) -> float:
    """Anytime-valid LOWER bound on the mean of an i.i.d. 0/1 sequence."""
    x = np.asarray(x)
    n1 = int(x.sum())
    return _betting_counts(len(x) - n1, n1, alpha, upper=False)
