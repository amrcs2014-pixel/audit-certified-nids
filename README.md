# Audit-certified blind spots for deployed intrusion detectors

Code, simulator and results for certifying what a deployed network intrusion detector (NIDS) **misses** on a new
network, from scarce and delayed labels, using a small budget of random **audits** and anytime-valid confidence
sequences. A manuscript based on this work is in preparation and is **not** included here.

The study is a **trace-driven simulation**:
- **Real detector scores** — every host-window score comes from a calibrated gradient-boosted detector trained on a
  real public NIDS dataset, with the attack family held out of training (a zero-day family).
- **Simulated SOC dynamics** — the analyst queue, discovery delay, never-discovered mass, and the audit channel are
  simulated. No real incident or audit log is used.
- **One real shift** — a year-apart deployment (train on CIC-IDS2017, certify on CSE-CIC-IDS2018) uses a genuinely
  later distribution; the detector and the shift are real, the SOC/label layer is still modeled.

## What it certifies

For a held-out ("zero-day") family on a new network:
- **Missed-compromise rate** `mu = P(host-window compromised AND not alerted)` — an anytime-valid upper bound from
  random audits, needing no label-delay model and no knowledge of the never-discovered share.
- **Recall** `= TP / (TP + FN)` — a lower bound via a joint certificate, made cheap by **stratified** auditing
  (audit the few, compromise-dense alerted host-windows; never lower-bound the rare prevalence directly).
- **Robustness** — the certificate stays valid, degrading gracefully, if audits can be partly evaded (parameter `eta`).

See `RESULTS_1b.md` for the full findings.

## Layout

| Path | What it is |
|---|---|
| `pom/cs.py` | Anytime-valid confidence sequences: empirical-Bernstein (`upper_at`) and the tighter betting-mixture (`upper_betting`, `lower_betting`). |
| `pom/data.py` | Detectors and per-family score pools, across five datasets; optional cross-year (`eval_dataset`). |
| `pom/accept.py` | Trace-driven acceptance simulator and the naive / IPCW / audit (ACE) estimators, with `audit_mode="stratified"` and `eta`-robust bounds. |
| `pom/run_multi.py` | Miss-rate + recall certificate across 5 datasets x 18 families. |
| `pom/run_strat.py` | Uniform vs stratified auditing for recall. |
| `pom/run_regimes.py` | Discovery-regime sweep (bias tracks the discovery process; certificate stays valid). |
| `pom/run_robust.py` | Certificate under bounded audit evasion `eta`. |
| `pom/run_temporal.py` | Real year-apart deployment CIC-IDS2017 -> CSE-CIC-IDS2018, with an analyst-hours cost. |
| `pom/run1b.py` | Single-dataset budget sweep (the original pilot). |
| `tests/` | Validity checks: confidence-sequence coverage, betting vs empirical-Bernstein, estimator unbiasedness. |
| `cache/` | Cached detector score pools (`pool_*.npz`) — enough to rerun every experiment **without the source datasets**. |
| `results/` | Reports (`*.md`), figures (`*.png`) and machine-readable results (`*.json`). |

## Reproduce

With Python 3.11+:

```bash
pip install -r requirements.txt
python -m tests.test_cs          # confidence-sequence coverage
python -m tests.test_betting     # betting vs empirical-Bernstein: coverage + tightness
python -m tests.test_accept      # simulator + estimator sanity
python -m pom.run_multi          # miss-rate + recall across datasets (results/multi.*)
python -m pom.run_strat          # uniform vs stratified recall budget (results/strat.*)
python -m pom.run_regimes        # discovery-regime sweep (results/regimes.*)
python -m pom.run_robust         # robustness under audit evasion (results/robust.*)
python -m pom.run_temporal       # real 2017->2018 deployment (results/temporal.*)
```

The runners read `cache/pool_*.npz`, so they reproduce every figure and table **without** the source datasets.

## Rebuilding the score pools from the original data

Only needed to retrain the detectors. The source datasets are not redistributed (their own licences apply):

| Dataset | Source |
|---|---|
| NF-ToN-IoT-v3, NF-UNSW-NB15-v3, NF-BoT-IoT-v3 | UQ NetFlow v3 datasets, <https://staff.itee.uq.edu.au/marius/NIDS_datasets/> |
| CIC-IDS2017 / CSE-CIC-IDS2018 (corrected) | Engelen et al. 2021; Liu et al. 2022 (improved releases) |
| UNSW-NB15 (standard set) | <https://research.unsw.edu.au/projects/unsw-nb15-dataset> |

Point the loader at your copies with environment variables (`POM_DATA_ROOT`, or the per-dataset
`POM_NF_TON_DIR` / `POM_NF_DIR` / `POM_CIC_DIR` / `POM_UNSW_DIR`), then delete `cache/pool_*.npz` to force a rebuild.

Please cite the dataset papers (NetFlow v3: Sarhan et al.; CIC-IDS corrections: Engelen et al. 2021, Liu et al. 2022;
UNSW-NB15: Moustafa & Slay 2015).

## Scope and honest limits

This is a **defensive** measurement tool: audits are honest and label delays benign; a bounded adversary appears only
as the sensitivity parameter `eta`. The SOC queue, discovery delay and audit oracle are simulated; the detectors and
the year-apart distribution shift are real. The certificates are conservative (coverage near 1.00). Auditing all alerts
is cheap as a fraction of host-windows but non-trivial in absolute analyst-hours at large fleet sizes.

## Related

This work follows up *Acting on Doubt* (AoD), which models the delayed, censored label channel these certificates
build on: <https://github.com/amrcs2014-pixel/acting-on-doubt> (DOI 10.5281/zenodo.23543240).
