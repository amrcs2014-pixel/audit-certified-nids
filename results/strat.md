# Stratified vs uniform auditing for recall certification

8 seeds, alpha=0.05. recall = TP/(TP+FN); stratified audits all alerts (pi_alert=1) plus a light non-alerted budget. Target floor = half the true recall.

| Dataset | Family | Recall | Budget for floor>=R/2 (uniform) | Budget (stratified) | speed-up |
|---|---|---|---|---|---|
| NF-ToN-IoT-v3 | xss | 0.15 | >cap | 0.9% | - |
| CIC-IDS2017 (improved) | web | 0.19 | >cap | 1.3% | - |
| CSE-CIC-IDS2018 (improved) | web | 0.20 | >cap | 2.1% | - |
| UNSW-NB15 (standard set) | shellcode | 0.27 | >cap | 2.7% | - |
| UNSW-NB15 (standard set) | fuzzers | 0.30 | >cap | 2.7% | - |
| UNSW-NB15 (standard set) | generic | 0.37 | 20.0% | 2.8% | 7.1x |
| UNSW-NB15 (standard set) | reconnaissance | 0.58 | 5.0% | 2.2% | 2.2x |
| CIC-IDS2017 (improved) | dos | 0.61 | 5.0% | 1.6% | 3.2x |

- Recall floors are valid everywhere (min coverage 1.00, target >= 0.95).
- A floor >= half the true recall is reached in 8/8 cells with stratified auditing vs 3/8 with uniform, within the swept budgets.
- Where both schemes reach it, stratified auditing needs a median 3.2x less budget.

Why: alerted host-windows are few and compromise-dense, so auditing them is cheap and gives a tight lower bound on TP (which dominates recall); the rare total prevalence never has to be lower-bounded directly. Stratum weights are known exactly and each stratum's audits are i.i.d., so the betting bounds stay anytime-valid.

Limits: same simulator caveats as the main run; auditing all alerts assumes alert volume is within analyst reach (it is small here); very-low-recall families stay hard because TP itself is tiny.