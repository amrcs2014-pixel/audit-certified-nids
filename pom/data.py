"""Detectors and per-family score pools for the 1b experiment, across several datasets.

All source data is read-only, from datasets already prepared on this machine:
- NetFlow-v3 family (identical 46-feature schema): NF-ToN-IoT-v3, NF-UNSW-NB15-v3, NF-BoT-IoT-v3.
- Improved (corrected) CIC-IDS2017 and CSE-CIC-IDS2018, CICFlowMeter features (Engelen/Liu release).

For each dataset and a held-out campaign family, a calibrated gradient-boosted binary detector (benign vs
attack) is trained with that family removed from train+calibration, so it is a zero-day family for the detector.
The pool stores per-family test scores (used by pom.accept) and calibration-split benign scores (for the
alert threshold). Leakage is controlled by splitting on a group id (NetFlow: 5-min start-time block; CIC:
contiguous row blocks within each source file).

Untrusted-data note: parquet files are read by explicit path with pandas; no code is executed from their folders.
"""
from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import GroupShuffleSplit

# Source datasets are not redistributed (see README). Point POM_DATA_ROOT at the folder holding the prepared
# files, or edit the paths below. The cached score pools in cache/ let the experiments rerun WITHOUT these.
ROOT = os.environ.get("POM_DATA_ROOT", r"E:\network research")
AOD_DATA = os.environ.get("POM_NF_TON_DIR", os.path.join(ROOT, "new3", "data"))
P28 = os.environ.get("POM_NF_DIR", os.path.join(ROOT, "p 28", "work", "data"))
CICDIR = os.environ.get("POM_CIC_DIR", os.path.join(ROOT, "weast", "p1", "improved-cicids2017-and-csecicids2018"))
CACHE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cache")

# NetFlow-v3 feature schema (fixed, public). Loaded from the dataset metadata if present, else this bundled copy,
# so cached-pool experiments run without the source datasets.
_NF_FEATS_FALLBACK = [
    "PROTOCOL", "L7_PROTO", "IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS", "TCP_FLAGS", "CLIENT_TCP_FLAGS",
    "SERVER_TCP_FLAGS", "FLOW_DURATION_MILLISECONDS", "DURATION_IN", "DURATION_OUT", "MIN_TTL", "MAX_TTL",
    "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT", "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN", "SRC_TO_DST_SECOND_BYTES",
    "DST_TO_SRC_SECOND_BYTES", "RETRANSMITTED_IN_BYTES", "RETRANSMITTED_IN_PKTS", "RETRANSMITTED_OUT_BYTES",
    "RETRANSMITTED_OUT_PKTS", "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT", "NUM_PKTS_UP_TO_128_BYTES",
    "NUM_PKTS_128_TO_256_BYTES", "NUM_PKTS_256_TO_512_BYTES", "NUM_PKTS_512_TO_1024_BYTES", "NUM_PKTS_1024_TO_1514_BYTES",
    "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT", "ICMP_TYPE", "ICMP_IPV4_TYPE", "DNS_QUERY_ID", "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER", "FTP_COMMAND_RET_CODE", "SRC_TO_DST_IAT_MIN", "SRC_TO_DST_IAT_MAX", "SRC_TO_DST_IAT_AVG",
    "SRC_TO_DST_IAT_STDDEV", "DST_TO_SRC_IAT_MIN", "DST_TO_SRC_IAT_MAX", "DST_TO_SRC_IAT_AVG", "DST_TO_SRC_IAT_STDDEV",
]
try:
    NF_FEATS = json.load(open(os.path.join(AOD_DATA, "nfton_v3.json")))["features"]
except (OSError, ValueError):
    NF_FEATS = _NF_FEATS_FALLBACK

NF_PATHS = {
    "nf_ton": os.path.join(AOD_DATA, "nfton_v3.parquet"),
    "nf_unsw": os.path.join(P28, "nfunsw_v3.parquet"),
    "nf_bot": os.path.join(P28, "nfbot_v3.parquet"),
}

UNSW_STD = os.environ.get("POM_UNSW_DIR", os.path.join(ROOT, "weast", "p1", "unsw-nb15"))

DATASET_TITLE = {
    "nf_ton": "NF-ToN-IoT-v3", "nf_unsw": "NF-UNSW-NB15-v3", "nf_bot": "NF-BoT-IoT-v3",
    "cic2017": "CIC-IDS2017 (improved)", "cic2018": "CSE-CIC-IDS2018 (improved)",
    "unsw_std": "UNSW-NB15 (standard set)",
}


def _load_unsw_std(seed: int, block=400) -> pd.DataFrame:
    df = pd.concat([pd.read_parquet(os.path.join(UNSW_STD, f"UNSW_NB15_{p}-set.parquet"))
                    for p in ("training", "testing")], ignore_index=True)
    df = df.rename(columns={c: c.lower() for c in df.columns})
    fam = df["attack_cat"].astype(str).str.lower().replace({"normal": "benign"})
    feats = [c for c in df.columns if c not in ("attack_cat", "label", "id")]
    out = pd.DataFrame(index=df.index)
    for c in feats:
        if df[c].dtype == object:
            out[c] = pd.factorize(df[c])[0]
        else:
            out[c] = pd.to_numeric(df[c], errors="coerce")
    out = out.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(np.float32)
    out["family"] = fam.values
    out["group"] = np.arange(len(out)) // block
    out.attrs["feats"] = [c for c in out.columns if c not in ("family", "group")]
    return out


def _cic_family(label: str) -> str:
    s = str(label).lower()
    if "benign" in s:
        return "benign"
    if "bot" in s:
        return "botnet"
    if "ddos" in s or "ddos" in s.replace(" ", ""):
        return "ddos"
    if s.startswith("dos") or "dos " in s or "hulk" in s or "goldeneye" in s or "slow" in s or "heartbleed" in s:
        return "dos"
    if "patator" in s or "bruteforce" in s or "brute force" in s or "brute-force" in s or "bruteforce" in s.replace(" ", ""):
        if "web" in s or "xss" in s or "sql" in s:
            return "web"
        return "bruteforce"
    if "web" in s or "xss" in s or "sql" in s:
        return "web"
    if "infil" in s:
        return "infiltration"
    if "portscan" in s or "port scan" in s:
        return "portscan"
    return re.sub(r"[^a-z0-9]+", "_", s).strip("_")


def _load_cic(year: str, seed: int, benign_cap=60000, fam_cap=30000, block=400) -> pd.DataFrame:
    pat = "*no-metadata*" if year == "2017" else "*_TrafficForML_CICFlowMeter*"
    files = sorted(glob.glob(os.path.join(CICDIR, pat)))
    rng = np.random.default_rng(seed)
    parts, gid = [], 0
    for f in files:
        df = pd.read_parquet(f)
        df["family"] = df["Label"].map(_cic_family)
        df = df.drop(columns=[c for c in df.columns if c == "Label"])
        # contiguous temporal blocks within the source file
        df = df.reset_index(drop=True)
        df["group"] = gid + (np.arange(len(df)) // block)
        gid = int(df["group"].max()) + 1
        parts.append(df)
    df = pd.concat(parts, ignore_index=True)
    # class-capped subsample (keeps whole groups' rows; cap is approximate per family)
    keep = []
    for fam, g in df.groupby("family"):
        cap = benign_cap if fam == "benign" else fam_cap
        keep.append(g if len(g) <= cap else g.sample(cap, random_state=seed))
    df = pd.concat(keep, ignore_index=True)
    feats = [c for c in df.columns if c not in ("family", "group")]
    for c in feats:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df[feats] = df[feats].replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(np.float32)
    df.attrs["feats"] = feats
    return df


def _load_nf(name: str) -> pd.DataFrame:
    df = pd.read_parquet(NF_PATHS[name], columns=NF_FEATS + ["family", "group"])
    df[NF_FEATS] = df[NF_FEATS].replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(np.float32)
    df.attrs["feats"] = NF_FEATS
    return df


def load(dataset: str, seed: int = 0) -> pd.DataFrame:
    if dataset in NF_PATHS:
        return _load_nf(dataset)
    if dataset == "cic2017":
        return _load_cic("2017", seed)
    if dataset == "cic2018":
        return _load_cic("2018", seed)
    if dataset == "unsw_std":
        return _load_unsw_std(seed)
    raise ValueError(dataset)


@dataclass
class Pool:
    dataset: str
    campaign: str
    test: dict
    cal_benign: np.ndarray
    meta: dict


def _split(groups: np.ndarray, seed: int):
    idx = np.arange(len(groups))
    tr, rest = next(GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=seed).split(idx, groups=groups))
    ca_r, te_r = next(GroupShuffleSplit(n_splits=1, test_size=0.6, random_state=seed + 1)
                      .split(rest, groups=groups[rest]))
    return tr, rest[ca_r], rest[te_r]


def build_pool(dataset: str, campaign: str, seed: int = 0, force: bool = False, eval_dataset: str = "") -> Pool:
    """Train a detector on `dataset` (campaign family held out), score its own test split.

    If `eval_dataset` is given and differs, this is a REAL temporal/cross-network deployment: the detector is
    trained on all of `dataset` (e.g. CIC-IDS2017) and certified on a genuinely later distribution
    `eval_dataset` (e.g. CSE-CIC-IDS2018). No family is held out there -- the "novelty" is the distribution
    shift itself, and the miss rate reflects real temporal degradation. Both datasets must share a schema.
    """
    os.makedirs(CACHE, exist_ok=True)
    cross = bool(eval_dataset) and eval_dataset != dataset
    tag = f"{dataset}_to_{eval_dataset}" if cross else dataset
    path = os.path.join(CACHE, f"pool_{tag}_x{campaign}_s{seed}.npz")
    if os.path.exists(path) and not force:
        z = np.load(path, allow_pickle=True)
        meta = json.loads(str(z["meta"]))
        test = {k[5:]: z[k] for k in z.files if k.startswith("test_")}
        return Pool(tag, campaign, test, z["cal_benign"], meta)

    df = load(dataset, seed)
    feats = df.attrs["feats"]
    X = df[feats].to_numpy(np.float32)
    fam = df["family"].to_numpy().astype(str)
    yb = (fam != "benign").astype(np.int64)
    tr, ca, te = _split(df["group"].to_numpy(), seed)
    if not cross:
        tr = tr[fam[tr] != campaign]
        ca = ca[fam[ca] != campaign]
    else:
        tr = np.concatenate([tr, ca, te])               # train on ALL of the source-year data
    base = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, random_state=seed)
    clf = CalibratedClassifierCV(base, method="isotonic", cv=3).fit(X[tr], yb[tr])

    if cross:
        de = load(eval_dataset, seed)
        Xe = de[feats].to_numpy(np.float32)
        fam = de["family"].to_numpy().astype(str)
        _, ca, te = _split(de["group"].to_numpy(), seed)
    else:
        Xe = X
    p_te = clf.predict_proba(Xe[te])[:, 1].astype(np.float64)
    p_ca = clf.predict_proba(Xe[ca])[:, 1].astype(np.float64)
    test = {f: np.sort(p_te[fam[te] == f]) for f in np.unique(fam[te])}
    cal_benign = np.sort(p_ca[fam[ca] == "benign"])
    meta = dict(dataset=tag, train_on=dataset, eval_on=eval_dataset or dataset, cross=cross, campaign=campaign,
                seed=seed, n_train=int(len(tr)), n_cal=int(len(ca)), n_test=int(len(te)),
                test_counts={f: int(len(v)) for f, v in test.items()}, features=len(feats))
    np.savez_compressed(path, cal_benign=cal_benign, meta=json.dumps(meta),
                        **{f"test_{f}": v for f, v in test.items()})
    return Pool(tag, campaign, test, cal_benign, meta)


if __name__ == "__main__":
    import sys
    for ds in (sys.argv[1:] or list(DATASET_TITLE)):
        df = load(ds)
        print(f"\n== {DATASET_TITLE[ds]}  n={len(df)}  feats={len(df.attrs['feats'])}")
        print("  families:", dict(df["family"].value_counts()))
