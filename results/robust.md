# Robust certification under audit evasion (eta)

8 seeds, alpha=0.05, stratified auditing. eta = worst-case probability that a truly missed compromise evades an audit (appears benign). This is a bounded adversary bound, not a simulated attack.

| Dataset | Family | Recall | floor @eta=0 | @0.1 | @0.2 | @0.3 |
|---|---|---|---|---|---|---|
| UNSW-NB15 (standard set) | reconnaissance | 0.58 | 0.46 | 0.43 | 0.40 | 0.37 |
| CIC-IDS2017 (improved) | dos | 0.61 | 0.48 | 0.45 | 0.42 | 0.39 |
| UNSW-NB15 (standard set) | generic | 0.37 | 0.27 | 0.25 | 0.23 | 0.21 |
| CIC-IDS2017 (improved) | web | 0.19 | 0.14 | 0.13 | 0.11 | 0.10 |

- The robust recall floor stays a valid lower bound at every eta (coverage min 1.00), and the robust miss-rate upper bound stays valid too (coverage min 1.00); targets $\ge0.95$.
- The floor degrades smoothly with eta (roughly by the factor $1-\eta$ through the FN term), so a deployment can state what its certificate guarantees even if audits are imperfectly evasion-resistant.
- This reclaims a defensive-robustness guarantee without modelling any specific attack: the certificate holds for the worst case within the eta budget.