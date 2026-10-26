# Pilot results: idea 1b (audit-certified miss rate on a new network)

Run: 26 Oct 2026, `pom/run1b.py`, 10 seeds, NF-ToN-IoT-v3 (reusing the AoD subsample, read-only).
Defensive only: honest operations, **no attacker model**. Estimand: `mu = P(host-window compromised AND not
alerted)`, the detector's missed-compromise rate for a held-out ("zero-day") family.

## Headline

Random audits of **0.5% of hosts per window** are enough to certify the miss rate within 2x of its true value
at 95% confidence. Naive and IPCW point estimates, which need a delay model and the never-discovered share,
read **15-17% low** and cannot certify at all.

## Numbers (campaign family = mitm, held out from training)

True miss rate mu = 0.0111 (detector recall on mitm = 0.07; a hard zero-day family).

| Estimator | Value | Can certify? |
|---|---|---|
| naive (discovered misses) | 0.0092 (17% low) | no |
| IPCW, assume full discovery | 0.0095 (15% low) | no |
| IPCW, oracle `p_never` | 0.0111 (unbiased) | needs the unknowable never-discovered share |
| **ACE audit upper bound** | see sweep | **yes, valid at every budget** |

| Audit budget (% hosts/win) | audits/win | coverage | median width / mu | within 2x (of 10 seeds) |
|---|---|---|---|---|
| 0.25% | 2.5 | 1.00 | 1.05 | 0.4 |
| **0.50%** | 5.0 | 1.00 | 0.80 | **0.9** |
| 1.00% | 10.0 | 1.00 | 0.52 | 1.0 |
| 2.00% | 20.0 | 1.00 | 0.32 | 1.0 |
| 5.00% | 50.0 | 1.00 | 0.21 | 1.0 |

Second family (ransomware, recall 0.001): identical conclusion, smallest budget 0.5%.

Figure: `results/run1b.png` (left: the certified bound tightening onto mu while naive/IPCW sit below it;
right: certificate width / mu vs budget).

## Why naive and IPCW fail (the honest, no-attacker point)

Even with honest, missing-at-random label delays, the share of missed compromises that are **never discovered**
(here 15%) is not identifiable from the analyst + discovery channels. IPCW is unbiased only if you plug in the
true `p_never`, which you do not know. Random audits reveal ground truth directly, so the ACE bound needs
neither a delay model nor `p_never`. This is the same identifiability point AoD states ("the never-discovered
share ... must come from audits"), here turned into a concrete audit budget.

## Validity evidence

- `tests/test_cs.py`: the anytime-valid bound has time-uniform miscoverage 0.2-1.1% against alpha = 0.05 on
  i.i.d.-rare, non-stationary, and audit-form sequences.
- `tests/test_accept.py`: ACE point estimate unbiased; ACE upper bound covers in 20/20 seeds; naive and
  full-discovery IPCW both read low.
- The sweep: coverage 1.00 at every budget (conservative, as expected for the empirical-Bernstein construction).

## Verdict against the pilot criterion

**Continue.** A small, purely defensive audit budget (0.5-1% of hosts/window) yields valid, useful certificates,
and the honest point estimators demonstrably cannot. This supports idea 1b as a standalone defensive paper.

## Honest limits of this pilot

- One dataset (NF-ToN-IoT-v3), host-windows synthesised from flow scores; no real host identities or timestamps.
- Single detector (calibrated HGB); compromise prevalence and discovery delays are swept-in assumptions, not measured.
- Certifies an absolute miss *rate*, not per-family recall as a ratio (needs joint bounds on prevalence; next step).
- The bound is conservative (coverage ~1.00); tighter betting variants (e.g. hedged/predictable mixtures) could
  reduce the budget further.
- No attacker is modelled. Adversarial control of the label channel is deliberately out of scope here.

## Files

- `pom/data.py` detector + per-family score pools (campaign held out).
- `pom/cs.py` anytime-valid upper confidence bound (empirical-Bernstein, lambda-mixture).
- `pom/accept.py` neutral acceptance simulator + naive/IPCW/ACE estimators.
- `pom/run1b.py` budget sweep, report and figure.
- `tests/test_cs.py`, `tests/test_accept.py` validity checks.

---

## Unified run across 5 datasets x 18 zero-day families

`pom/run_multi.py`, 8 seeds, budgets {0.25, 0.5, 1, 2, 5}% of hosts/window. Full table and figure:
`results/multi.md`, `results/multi.png`, `results/multi.json`. Each cell holds out one family (recall < ~0.6,
so there is a real miss rate to certify).

Datasets: NF-ToN-IoT-v3, UNSW-NB15 (standard CICFlowMeter set), NF-BoT-IoT-v3, CIC-IDS2017 (improved),
CSE-CIC-IDS2018 (improved). Families span recall 0.001 (ransomware) to 0.61 (CIC2017 dos).

Findings, consistent across all 18 cells:
- **ACE coverage = 1.00** at every cell and budget (conservative, target >= 0.95).
- **Smallest certifying budget met in 18/18 cells; median 0.5% of hosts/window** (1.0% in the higher-recall,
  rarer-miss cells, as expected: fewer missed compromises need slightly more audits).
- **naive bias -16.8% and IPCW(full-discovery) bias -14.9% on average** -- both read low and cannot certify.
  The relative bias is near-constant across datasets/families because it is governed by the discovery process
  (never-discovered share + horizon), not by the detector: a structural, not dataset-specific, blindness.

### UNSW finding (reported, not hidden)
On the NetFlow-v3 form of UNSW-NB15 (NF-UNSW-NB15-v3), the benign/attack boundary is so separable that the
detector catches every held-out family (recall ~1.0, mu ~ 0), leaving no miss rate to certify. UNSW is therefore
covered through its standard CICFlowMeter feature set, where held-out families (shellcode, fuzzers, generic,
reconnaissance) are genuinely missed (recall 0.27-0.58). This is a known over-separability artifact of the
NetFlow-v3 UNSW labels, worth a sentence in the paper.

---

## Methodological upgrades: tighter bound + recall as a ratio

Two additions (`pom/cs.py` betting-mixture CS; `pom/accept.py` recall certificate), 8 seeds, budgets up to 20%.
Figure `results/multi.png` (3 panels), table `results/multi.md`.

**1. Tighter miss-rate bound (betting mixture).** A confidence sequence built from a mixture of constant-bet
capital processes. Because the audit indicators are 0/1, the bound is an exact function of the audit counts
(n0, n1), so it is both tight and instant. It is **a median ~4% narrower** than the empirical-Bernstein bound
at the same budget, with coverage preserved (min coverage 1.00 across all cells and budgets). Validity uses that
host-windows are i.i.d. in this simulator; the empirical-Bernstein bound (kept as the baseline) also covers the
non-i.i.d. case. The gain is modest because the EB mixture was already near-optimal in this conservative
anytime-valid regime; the betting CS matters more as the machinery for the two-sided recall bound.

**2. Recall as a ratio with a joint certificate.** recall = 1 - mu / prevalence, certified by an upper bound on
mu and a lower bound on prevalence (both from audits, betting CS at alpha/2 each -> overall alpha). Findings:
- Valid everywhere: the recall floor never exceeded the true recall in any cell x budget (coverage 1.00).
- **Much more expensive than the miss rate.** Certifying prevalence from below needs enough audited *compromised*
  host-windows, which are rare (prevalence x budget). A recall floor >= half the true recall was reached in only
  3/18 cells, at a median budget of 5% of hosts/window -- versus 0.5% for the absolute miss rate.
- **Informative only for moderate-to-high-recall families.** For reconnaissance (R=0.58) the floor reaches 0.31 at
  5% and ~0.45 at 20%; for CIC-IDS2017 dos (R=0.61), 0.35 at 5%. For near-zero-recall families the floor stays 0 --
  correct (the true recall is ~0) but uninformative.
- **Next lever:** score-stratified audits with known propensities (audit suspected-compromised host-windows more
  often, reweight by Horvitz-Thompson) would concentrate the budget on the rare compromised class and cut the
  recall budget sharply. That needs a bounded-IPW betting CS and is the natural follow-up.

Net: the absolute miss-rate certificate is cheap and robust (0.5-1% budget, ~4% tighter with betting); the recall
ratio is a valid but costlier object, useful mainly where the detector has non-trivial recall, and a clear target
for stratified auditing.

---

## Stratified auditing cuts the recall-certification budget

Added a stratified audit scheme (`pom/accept.py` audit_mode="stratified"; `pom/run_strat.py`). It uses the identity
**recall = TP / (TP + FN)**, TP = P(compromised & alerted), FN = P(compromised & not alerted) = mu, and audits:
- all **alerted** host-windows (they are few, and compromise-dense) -> a tight lower bound on TP;
- a light sample of the huge **non-alerted** stratum -> an upper bound on FN.

Stratum weights are known exactly (every host-window's alert status is observed) and each stratum's audits are
i.i.d., so the per-stratum betting bounds stay anytime-valid; recall_lower = L(TP)/(L(TP)+U(FN)) at alpha/2 each.
This never has to lower-bound the rare total prevalence directly -- the key efficiency win.

Result (8 moderate/high-recall cells, target floor = half the true recall; `results/strat.md`, `results/strat.png`):

| Family (recall) | Uniform budget for floor>=R/2 | Stratified budget | Speed-up |
|---|---|---|---|
| CIC2017 web (0.19) | not reached by 20% | **1.3%** | - |
| CIC2018 web (0.20) | not reached by 20% | **2.1%** | - |
| UNSW shellcode (0.27) | not reached | **2.7%** | - |
| UNSW fuzzers (0.30) | not reached | **2.7%** | - |
| UNSW generic (0.37) | 20.0% | **2.8%** | 7.1x |
| UNSW reconnaissance (0.58) | 5.0% | **2.2%** | 2.2x |
| CIC2017 dos (0.61) | 5.0% | **1.6%** | 3.2x |
| NF-ToN xss (0.15) | not reached | **0.9%** | - |

- Valid everywhere (min coverage 1.00).
- A recall floor >= half the true recall is reached in **8/8 cells with stratified auditing vs 3/8 uniform**;
  where both reach it, stratified needs a **median 3.2x less budget**, and it makes previously-vacuous cells
  (e.g. CIC web, R~0.2) certifiable at ~1-2%.
- Very-low-recall families remain hard because TP itself is tiny -- but there the true recall is near zero anyway.

Net across the three method upgrades: the absolute miss rate certifies at 0.5-1% (betting bound ~4% tighter than
empirical-Bernstein); recall as a ratio, with stratified auditing, now certifies a useful floor at ~1-3% instead
of >5-20% (or not at all) under uniform auditing.

---

## Paper draft

A compiling LaTeX draft of the 1b paper is in `paper/`:
- `paper/main.tex` (7 pages): abstract, intro, related work, setup, non-identification proposition,
  audit-certified miss rate, recall-as-ratio, stratified auditing, experiments (2 tables + 2 figures), discussion.
- `paper/make_tables.py` regenerates `paper/tables/tab_multi.tex` and `tab_strat.tex` from `results/*.json`
  so the numbers stay in sync with the runs.
- `paper/refs.bib` (entries marked VERIFY are scan-sourced and must be checked before submission).
- Build: `python paper/make_tables.py && cd paper && pdflatex main && bibtex main && pdflatex main && pdflatex main`.

Retarget to IEEEtran/llncs and add real author list before submission. Keep separate from AoD and cite it.

---

## References verified (2026-10-26)

All `paper/refs.bib` entries were checked against Scopus / publisher pages / arXiv; no VERIFY tags remain.
- Fixed: the CALIBURN entry pointed at arXiv:2605.24696, which is a *different* paper -- replaced with a verified
  conformal-IDS reference (CRISP, Moccardi et al., MLISE 2026) and adjusted the related-work sentence.
- Completed metadata (authors, venue, pages, DOIs) for: Botacin & Gomes (C&S 148:104122, 2025); OWAD (NDSS 2023);
  DualGuard (TIFS 2026, 10.1109/TIFS.2026.3744632); Transcend (USENIX Sec 2017, pp.625-642); Waudby-Smith & Ramdas
  (JRSSB 2024, 10.1093/jrsssb/qkad009); Howard et al. (Ann. Stat. 49(2):1055-1080, 2021); Podkopaev & Ramdas (ICLR
  2022); PPI (Science 382:669-674, 2023); Zrnic & Candes (ICML 2024, pp.62993-63010); Engelen et al. (SPW 2021,
  pp.7-12); Liu et al. (CNS 2022, pp.254-263); Olimpio et al. (C&S 134:103451, 2023).
- AoD entry kept as under-review `@misc` (no public venue yet). The draft now compiles to 8 pages with no bibtex
  warnings and no undefined citations.

---

## Strengthening pass (addresses the reviewer critique)

Implemented all five "raise it to a strong paper" points; code in `pom/run_regimes.py`, `pom/run_robust.py`,
`pom/run_temporal.py`, and `eta`/`eval_dataset` support in `pom/accept.py`+`pom/data.py`.

1. **Regime sweep turns the "baked-in bias" into a finding** (`results/regimes.*`). The naive bias runs from -2%
   at p_never=0 to -41% at p_never=0.4, and -16% (fast discovery) to -41% (slow), and is flat in prevalence --
   i.e. it tracks the discovery process exactly as Proposition 1 predicts. ACE coverage stays 1.00 in every regime.
2. **Robust certificate under bounded audit evasion** (`results/robust.*`). With eta = worst-case probability a
   missed compromise evades an audit, the robust recall floor = TP_lo/(TP_lo + FN_up/(1-eta)) stays valid (coverage
   1.00) and degrades smoothly (e.g. CIC2017/dos 0.48->0.39 as eta 0->0.3). A defensive guarantee, no attack simulated.
3. **Real year-apart deployment** (`results/temporal.*`): train on CIC-IDS2017, certify on CSE-CIC-IDS2018 (no family
   held out). A 2017-trained detector misses evolved 2018 attacks almost entirely -- certified recall floors 0.01
   (botnet), 0.01 (bruteforce), 0.01 (infiltration), 0.02 (web); only dos keeps recall (0.35, floor 0.27). Naive
   monitoring reads -17% low; audit certificate covers. This is the realism centerpiece (detector + shift are real).
4. **Analyst-hours operating point**: audit budget translated at 10 min/host-window-hunt; ~hundreds of analyst-h/week
   at this fleet size, dominated by auditing alerts -- reported honestly as a cost, tunable by sub-sampling alerts.
5. **Paper re-centered on stratified certification**: `paper/main.tex` rewritten (8 pp), stratified recall is now the
   headline contribution; regimes, robustness, and the year-apart deployment are new sections/experiments. Tables
   auto-generated (`paper/make_tables.py` now also emits `tab_temporal.tex`). Compiles clean, 0 undefined, 0 bibtex
   warnings.

Runners: `python -m pom.run_regimes | pom.run_robust | pom.run_temporal` from `pilot/`.

---

## Second critical pass (writing + arguments)

Revised `paper/main.tex` after a second professorial review:
- **Proposition 1 made precise**: states the identified set [discovered-rate, +unlabelled mass] and that only IPCW
  with the *true* p_never is unbiased; any assumed p' < p_never is biased by (1-p_never)/(1-p'). Fixes the earlier
  statement that wrongly implied all IPCW reads low.
- **"exact coverage" -> "conservative, time-uniform coverage"** (1.00 > 0.95 is over-coverage, not exact).
- **Analyst-hours corrected**: ~880 h/week (~0.9 h/host/week), stated honestly as a real, fleet-scaling cost, not
  "a few hundred."
- **DDoS coverage 0.88 acknowledged** in the temporal result (within sampling noise at 8 seeds), not hidden.
- **Abstract recall-floor range tightened** to 0.01-0.02 (was 0.01-0.05).
- **"within 2x" justified**: order-of-magnitude assurance drives deploy/retrain for a rare rate.
- **Positioning strengthened**: added TESSERACT (temporal/spatial eval bias) and owned the classical lineage of the
  stratified method (Horvitz-Thompson, Neyman allocation) -- claiming novelty only in the recall identity that lets
  Neyman allocation skip the prevalence, not in stratified sampling itself.
- **Betting bound explicitly downgraded** from "contribution" to "minor refinement, for completeness."
- Audit-as-threat-hunt oracle made explicit in setup and tied to the robustness section.
Compiles clean (8 pp, 0 undefined, 0 bibtex warnings). New refs in refs.bib: tesseract, horvitz1952, neyman1934.
