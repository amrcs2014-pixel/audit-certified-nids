# Unified 1b results: audit-certified miss rate and recall across datasets

8 seeds, budgets [0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0]% of hosts/window, alpha=0.05. No attacker modelled. Miss rate mu = P(host-window compromised by the held-out family AND not alerted); recall = 1 - mu/prevalence, certified by a joint (upper mu, lower prevalence) bound at alpha/2 each. The miss-rate upper bound uses the betting-mixture confidence sequence (tighter than empirical-Bernstein).

| Dataset | Zero-day family | Recall | True mu | naive bias | mu budget (<=2x) | betting vs EB | recall floor @5% | recall budget |
|---|---|---|---|---|---|---|---|---|
| NF-ToN-IoT-v3 | ransomware | 0.001 | 0.0119 | -16.8% | 0.5% | -4% w | 0.00 | >20% |
| NF-ToN-IoT-v3 | backdoor | 0.002 | 0.0119 | -16.8% | 0.5% | -4% w | 0.00 | >20% |
| NF-ToN-IoT-v3 | mitm | 0.072 | 0.0111 | -16.7% | 0.5% | -4% w | 0.00 | >20% |
| NF-ToN-IoT-v3 | xss | 0.148 | 0.0102 | -16.6% | 0.5% | -3% w | 0.00 | >20% |
| UNSW-NB15 (standard set) | shellcode | 0.275 | 0.0087 | -16.7% | 0.5% | -4% w | 0.00 | >20% |
| UNSW-NB15 (standard set) | fuzzers | 0.298 | 0.0084 | -16.7% | 1.0% | -3% w | 0.00 | >20% |
| UNSW-NB15 (standard set) | generic | 0.375 | 0.0075 | -16.8% | 1.0% | -4% w | 0.04 | 20.0% |
| UNSW-NB15 (standard set) | reconnaissance | 0.584 | 0.0050 | -17.4% | 1.0% | -4% w | 0.31 | 5.0% |
| NF-BoT-IoT-v3 | theft | 0.050 | 0.0113 | -16.7% | 0.5% | -3% w | 0.00 | >20% |
| NF-BoT-IoT-v3 | reconnaissance | 0.093 | 0.0108 | -16.8% | 0.5% | -3% w | 0.00 | >20% |
| CIC-IDS2017 (improved) | botnet | 0.008 | 0.0118 | -16.7% | 0.5% | -4% w | 0.00 | >20% |
| CIC-IDS2017 (improved) | bruteforce | 0.019 | 0.0117 | -16.8% | 0.5% | -4% w | 0.00 | >20% |
| CIC-IDS2017 (improved) | web | 0.195 | 0.0096 | -16.5% | 0.25% | -4% w | 0.00 | >20% |
| CIC-IDS2017 (improved) | dos | 0.607 | 0.0047 | -17.5% | 1.0% | -4% w | 0.35 | 5.0% |
| CSE-CIC-IDS2018 (improved) | bruteforce | 0.014 | 0.0118 | -16.8% | 0.5% | -4% w | 0.00 | >20% |
| CSE-CIC-IDS2018 (improved) | infiltration | 0.041 | 0.0114 | -16.7% | 1.0% | -3% w | 0.00 | >20% |
| CSE-CIC-IDS2018 (improved) | ddos | 0.091 | 0.0108 | -16.8% | 0.5% | -4% w | 0.00 | >20% |
| CSE-CIC-IDS2018 (improved) | web | 0.197 | 0.0096 | -16.6% | 0.5% | -3% w | 0.00 | >20% |

- Cells: 18. Mean naive bias -16.8% (point estimates read low and cannot certify).
- **Miss-rate certificate** coverage over all cells x budgets: min 1.00 (target >= 0.95); certified within 2x in 18/18 cells, median budget 0.5% of hosts/window.
- **Tighter bound:** the betting-mixture CS is a median 4% narrower than empirical-Bernstein at the same budget, with coverage preserved.
- **Recall as a ratio** (joint bound) is valid everywhere (min coverage 1.00) but costs more: a recall floor >= half the true recall is reached in 3/18 cells, median budget 5.0%. It is vacuous for near-zero-recall families (where the true recall is ~0, so the floor of 0 is correct but uninformative) and most useful for moderate-recall families.

Honest limits: synthetic host-windows from flow scores; one detector family per dataset; fixed compromise prevalence and discovery-delay assumptions; uniform (non-stratified) audits -- score-stratified audits with known propensities would cut the recall budget and are the next step; the bounds are conservative (coverage ~1.00).