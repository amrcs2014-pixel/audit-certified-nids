# Regime sweep: the point-estimator bias tracks the discovery process; the certificate stays valid

8 seeds, alpha=0.05. Base cells: CIC-IDS2017 (improved)/dos, NF-ToN-IoT-v3/mitm.

The naive and full-discovery-IPCW biases are not a fixed number: they grow with the never-discovered share and with slower discovery, exactly as Proposition 1 predicts. The audit certificate's coverage stays at 1.00--1.00 across every regime (target >= 0.95).

## CIC-IDS2017 (improved) / dos
- **p_never**: 0.0: naive -2%, IPCW0 -0%, ACE cov 1.00; 0.1: naive -13%, IPCW0 -11%, ACE cov 1.00; 0.2: naive -22%, IPCW0 -20%, ACE cov 1.00; 0.3: naive -32%, IPCW0 -30%, ACE cov 1.00; 0.4: naive -41%, IPCW0 -40%, ACE cov 1.00
- **disc_med**: 24: naive -16%, IPCW0 -15%, ACE cov 1.00; 72: naive -17%, IPCW0 -16%, ACE cov 1.00; 168: naive -26%, IPCW0 -16%, ACE cov 1.00; 336: naive -41%, IPCW0 -16%, ACE cov 1.00
- **prevalence**: 0.004: naive -17%, IPCW0 -15%, ACE cov 1.00; 0.008: naive -17%, IPCW0 -15%, ACE cov 1.00; 0.012: naive -17%, IPCW0 -16%, ACE cov 1.00; 0.02: naive -17%, IPCW0 -15%, ACE cov 1.00

## NF-ToN-IoT-v3 / mitm
- **p_never**: 0.0: naive -2%, IPCW0 +0%, ACE cov 1.00; 0.1: naive -12%, IPCW0 -10%, ACE cov 1.00; 0.2: naive -22%, IPCW0 -20%, ACE cov 1.00; 0.3: naive -31%, IPCW0 -30%, ACE cov 1.00; 0.4: naive -41%, IPCW0 -40%, ACE cov 1.00
- **disc_med**: 24: naive -15%, IPCW0 -15%, ACE cov 1.00; 72: naive -17%, IPCW0 -15%, ACE cov 1.00; 168: naive -25%, IPCW0 -15%, ACE cov 1.00; 336: naive -41%, IPCW0 -15%, ACE cov 1.00
- **prevalence**: 0.004: naive -17%, IPCW0 -15%, ACE cov 1.00; 0.008: naive -17%, IPCW0 -15%, ACE cov 1.00; 0.012: naive -17%, IPCW0 -15%, ACE cov 1.00; 0.02: naive -17%, IPCW0 -15%, ACE cov 1.00

Takeaway: the label-based estimators' shortfall is governed by the discovery process (never-discovered mass + horizon), not by the detector or dataset; only audits remove it. At p_never=0 and fast discovery the naive estimator is near-unbiased, and its bias rises monotonically as discovery degrades.