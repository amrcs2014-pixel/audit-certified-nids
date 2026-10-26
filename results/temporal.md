# Real temporal deployment: train on CIC-IDS2017, certify on CSE-CIC-IDS2018

8 seeds, alpha=0.05, stratified auditing. The detector is trained on all of 2017 and deployed on 2018 (a real year-apart distribution); no family is held out, so the miss rate is real temporal degradation. Audit cost is translated to analyst-hours at 10 min per host-window hunt over 21 days.

| 2018 family | Recall (2017-trained) | True $\mu$ | naive bias | miss-rate cov | recall floor | recall cov | analyst-h/week |
|---|---|---|---|---|---|---|---|
| bruteforce | 0.017 | 0.0117 | -17% | 1.00 | 0.01 | 1.00 | 878 |
| botnet | 0.012 | 0.0118 | -17% | 1.00 | 0.01 | 1.00 | 876 |
| ddos | 0.077 | 0.0110 | -17% | 0.88 | 0.05 | 1.00 | 897 |
| dos | 0.347 | 0.0078 | -17% | 1.00 | 0.27 | 1.00 | 986 |
| infiltration | 0.026 | 0.0116 | -17% | 1.00 | 0.01 | 1.00 | 880 |
| web | 0.027 | 0.0116 | -17% | 1.00 | 0.02 | 1.00 | 880 |

- The year-apart deployment is a real stress test: a 2017-trained detector misses evolved 2018 attacks almost entirely (e.g. botnet, recall 0.01), and the audit certificate quantifies it from scarce labels.
- Naive label-based monitoring still reads the miss rate low; the audit certificate covers the true miss rate (coverage near 1.00).
- Cost: certifying these took roughly 899 analyst-hours per week on average (most of it auditing the few alerted host-windows), a concrete operating point for a deployment team.

Limit: 2017->2018 share the CICFlowMeter schema and are a standard cross-year benchmark; the SOC queue, delay, and audit oracle are still modeled.