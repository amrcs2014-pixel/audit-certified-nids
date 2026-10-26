"""Acceptance testing of a NIDS on a new network (idea 1b, defensive only).

Question: with scarce, delayed labels, how many random audits does it take to CERTIFY a detector's
missed-compromise rate on a new network before trusting it?

This module models honest operations only. There is no attacker:
- compromise status of a host-window is drawn at random with a fixed prevalence;
- detector scores are real test-split scores from NF-ToN-IoT-v3 (pom.data), campaign family held out;
- label channels are honest and missing-at-random:
    * discovery: a MISSED compromise (not alerted) is discovered after a log-normal delay, or never;
    * audit: each host-window is audited with a known constant probability pi (reveals ground truth).

Estimand (per host-window):  mu = P(compromised AND not alerted)  -- the detector's missed-compromise rate.
True mu is known in simulation, so we can score every estimator's bias and the certificate's coverage.

Estimators of mu at the analysis horizon:
- naive : (discovered missed compromises) / N                         -> biased low (not-yet + never discovered)
- ipcw  : sum over discovered missed of 1/G(age) / N, with the TRUE discovery CDF G (incl. never-discovered
          ceiling 1 - p_never). Unbiased only if p_never is known -- which is not identifiable from labels.
- ipcw0 : same, but assuming everything is eventually discovered (p_never = 0) -> biased.
- ace   : audit inverse-probability estimate + anytime-valid UPPER bound (pom.cs). Needs no delay model and
          no knowledge of p_never; audits reveal truth directly.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.stats import norm

from .cs import upper_at, upper_betting, lower_betting
from .data import build_pool


@dataclass
class Cfg:
    H: int = 1000
    days: int = 21
    dataset: str = "nf_ton"
    campaign: str = "mitm"
    prevalence: float = 0.012        # P(host-window compromised by the campaign family)
    n_benign_mean: float = 4.0
    fp_target: float = 0.01          # planned benign host-window alert rate (set on calibration split)
    disc_med: float = 72.0           # discovery delay from onset (windows), log-normal
    disc_sigma: float = 1.0
    p_never: float = 0.15            # share of missed compromises never discovered
    grace_days: float = 14.0         # extra time after the deployment window for late discoveries
    audit_budget: float = 0.0        # UNIFORM mode: audits/window; STRATIFIED mode: audits/window of unalerted stratum
    audit_mode: str = "uniform"      # 'uniform' or 'stratified' (audit alerted vs non-alerted at known propensities)
    pi_alert: float = 1.0            # STRATIFIED: probability of auditing an alerted host-window (alerts are few)
    eval_dataset: str = ""           # if set and != dataset: real cross-year/cross-network deployment (train->eval)
    seed_pool: int = 0
    alpha: float = 0.05


def threshold_for(cal_benign: np.ndarray, fp_target: float, n_mean: float) -> float:
    """lambda with P(max over 1+Poisson(n_mean) benign flows >= lambda) ~= fp_target (calibration split)."""
    for lam in np.unique(cal_benign):
        p = np.mean(cal_benign >= lam)
        fp = 1.0 - (1.0 - p) * np.exp(-n_mean * p)
        if fp <= fp_target:
            return float(lam)
    return float(cal_benign[-1])


def _max_of_n(rng, pool_sorted, n):
    n = np.asarray(n)
    u = rng.random(n.shape) ** (1.0 / n)
    return pool_sorted[np.minimum((u * len(pool_sorted)).astype(np.int64), len(pool_sorted) - 1)]


def G_hat(age, med, sigma, p_never):
    age = np.asarray(age, dtype=float)
    out = np.zeros_like(age)
    pos = age > 0
    out[pos] = (1 - p_never) * norm.cdf((np.log(age[pos]) - np.log(med)) / sigma)
    return out


@dataclass
class Run:
    cfg: Cfg
    lam: float
    N: int
    recall: float
    mu_true: float
    prevalence_true: float
    missed: np.ndarray        # (N,) bool, host-window order (window, then host)
    compromised: np.ndarray   # (N,) bool
    alerted: np.ndarray       # (N,) bool
    audit: np.ndarray         # (N,) bool
    pi: float
    disc_window: np.ndarray   # (N,) int, horizon+1 if not discovered by horizon
    onset_window: np.ndarray  # (N,) int (the window index), -1 if not a missed compromise
    T_end: int


def simulate(cfg: Cfg, seed: int) -> Run:
    rng = np.random.default_rng(seed)
    pool = build_pool(cfg.dataset, cfg.campaign, cfg.seed_pool, eval_dataset=cfg.eval_dataset)
    ben = pool.test["benign"]
    camp = pool.test[cfg.campaign]
    lam = threshold_for(pool.cal_benign, cfg.fp_target, cfg.n_benign_mean)
    H, W = cfg.H, 24 * cfg.days
    N = H * W
    T_end = W + int(24 * cfg.grace_days)

    comp = rng.random((W, H)) < cfg.prevalence
    nb = 1 + rng.poisson(cfg.n_benign_mean, (W, H))
    score = _max_of_n(rng, ben, nb)
    ch = np.nonzero(comp.ravel())[0]
    if len(ch):
        kc = 1 + rng.poisson(2.0, len(ch))
        cs = _max_of_n(rng, camp, kc)
        flat = score.ravel()
        flat[ch] = np.maximum(flat[ch], cs)
        score = flat.reshape(W, H)
    alerted = score >= lam
    missed2d = comp & ~alerted                        # detector miss

    win_idx = np.repeat(np.arange(W), H)              # window of each host-window (row-major)
    missed = missed2d.ravel()
    compromised = comp.ravel()
    recall = 1.0 - missed.sum() / max(1, comp.sum())
    mu_true = missed.mean()
    prevalence_true = compromised.mean()

    # discovery channel for missed compromises (honest, missing-at-random)
    disc_window = np.full(N, T_end + 1, np.int64)
    onset = np.where(missed, win_idx, -1)
    mi = np.nonzero(missed)[0]
    if len(mi):
        age = np.exp(np.log(cfg.disc_med) + cfg.disc_sigma * rng.standard_normal(len(mi)))
        never = rng.random(len(mi)) < cfg.p_never
        dw = win_idx[mi] + np.ceil(age).astype(np.int64)
        dw[never] = T_end + 1
        disc_window[mi] = dw

    # audit channel with known propensities
    alerted_flat = alerted.ravel()
    coin = rng.random(N)
    if cfg.audit_mode == "stratified":
        pi_u = min(1.0, cfg.audit_budget / H) if cfg.audit_budget > 0 else 0.0
        audit = ((alerted_flat & (coin < cfg.pi_alert)) | (~alerted_flat & (coin < pi_u)))
        pi = pi_u
    else:
        pi = min(1.0, cfg.audit_budget / H) if cfg.audit_budget > 0 else 0.0
        audit = coin < pi if pi > 0 else np.zeros(N, bool)

    return Run(cfg, lam, N, float(recall), float(mu_true), float(prevalence_true),
               missed, compromised, alerted_flat, audit, pi, disc_window, onset, T_end)


def estimates(run: Run, eta: float = 0.0):
    """Point estimates at the horizon, plus the ACE anytime-valid upper bound at the horizon.

    eta in [0,1): robustness to audit evasion. If a truly missed compromise can appear benign to an audit with
    probability up to eta (a bounded, worst-case adversary -- no attack is simulated), the observed audited-miss
    rate reads low by a factor (1-eta), so a robust upper bound on the miss rate is U/(1-eta). TP lower bounds
    stay valid under evasion (they only get more conservative). We report both the nominal and the eta-robust
    certificates; eta=0 recovers the nominal bound.
    """
    cfg, N, T = run.cfg, run.N, run.T_end
    rob = 1.0 - min(max(eta, 0.0), 0.95)
    disc = run.disc_window <= T                        # discovered by horizon
    missed_disc = run.missed & disc
    naive = missed_disc.sum() / N

    age = np.where(run.missed, T - run.onset_window, 0.0)
    g_true = G_hat(age, cfg.disc_med, cfg.disc_sigma, cfg.p_never)
    g0 = G_hat(age, cfg.disc_med, cfg.disc_sigma, 0.0)
    w_true = np.where(missed_disc, 1.0 / np.maximum(g_true, 1e-6), 0.0)
    w0 = np.where(missed_disc, 1.0 / np.maximum(g0, 1e-6), 0.0)
    ipcw = w_true.sum() / N
    ipcw0 = w0.sum() / N

    # realized audit cost as % of hosts per window = total audits / (windows * hosts) = n_audits / N
    out = dict(mu_true=run.mu_true, recall=run.recall, prevalence=run.prevalence_true,
               naive=naive, ipcw=ipcw, ipcw0=ipcw0, n_audits=int(run.audit.sum()),
               audit_pct=100.0 * run.audit.sum() / run.N)
    if run.cfg.audit_mode == "stratified" and run.audit.any():
        # recall = TP / (TP + FN), TP = P(comp & alert), FN = P(comp & not alert) = mu.
        # Known exact stratum weights w_A, w_U (every host-window's alert status is observed); within each
        # stratum the audited items are i.i.d. Bernoulli, so the 0/1 betting CS applies. recall is increasing
        # in TP and decreasing in FN, so recall_lower = L(TP) / (L(TP) + U(FN)) with alpha/2 on each side.
        a = cfg.alpha
        A = run.alerted
        U = ~A
        wA = A.mean()
        wU = U.mean()
        cA = run.compromised[run.audit & A].astype(float)   # comp | alerted (audited)
        mU = run.missed[run.audit & U].astype(float)         # missed | unalerted (audited) == comp&~alert|U
        TP_lo = wA * lower_betting(cA, a / 2) if len(cA) else 0.0
        FN_up = wU * upper_betting(mU, a / 2) if len(mU) else wU
        FN_up_rob = FN_up / rob
        recall_lo = TP_lo / (TP_lo + FN_up) if (TP_lo + FN_up) > 0 else 0.0
        recall_lo_rob = TP_lo / (TP_lo + FN_up_rob) if (TP_lo + FN_up_rob) > 0 else 0.0
        out.update(ace_point=float(mU.mean() * wU) if len(mU) else np.nan,
                   ace_upper=FN_up, ace_upper_mix=FN_up, ace_upper_robust=FN_up_rob,
                   recall_lower=recall_lo, recall_lower_robust=recall_lo_rob,
                   mu_upper_h=FN_up, p_lower=TP_lo,
                   n_audit_missed=int(mU.sum()) if len(mU) else 0,
                   n_audit_comp=int(cA.sum()) if len(cA) else 0,
                   n_audit_alert=int((run.audit & A).sum()))
        return out
    if run.pi > 0 and run.audit.any():
        aud = run.audit
        r_miss = run.missed[aud].astype(float)         # i.i.d. Bernoulli(mu) over audited host-windows
        r_comp = run.compromised[aud].astype(float)    # i.i.d. Bernoulli(prevalence)
        a = cfg.alpha
        # miss-rate certificate: betting (tight) and empirical-Bernstein (comparison), on the audited subsample
        U_bet = upper_betting(r_miss, a)
        U_mix = float(upper_at(r_miss, [len(r_miss)], a)[0])
        ace_point = float(r_miss.mean())
        # recall as a ratio: recall = 1 - mu/p, with a joint certificate (alpha/2 each -> overall alpha)
        mu_up = upper_betting(r_miss, a / 2)
        p_lo = lower_betting(r_comp, a / 2)
        recall_lo = max(0.0, 1.0 - mu_up / p_lo) if p_lo > 0 else 0.0
        out.update(ace_point=ace_point, ace_upper=U_bet, ace_upper_mix=U_mix, ace_upper_robust=U_bet / rob,
                   recall_lower=recall_lo, recall_lower_robust=recall_lo, mu_upper_h=mu_up, p_lower=p_lo,
                   n_audit_missed=int(r_miss.sum()), n_audit_comp=int(r_comp.sum()))
    else:
        out.update(ace_point=np.nan, ace_upper=np.nan, ace_upper_mix=np.nan,
                   recall_lower=np.nan, mu_upper_h=np.nan, p_lower=np.nan,
                   n_audit_missed=0, n_audit_comp=0)
    return out
