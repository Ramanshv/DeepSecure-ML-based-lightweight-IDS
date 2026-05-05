"""
src/dataset_loader.py – Loads and splits NSL-KDD, CICIDS-2017, and UNSW-NB15.

NSL-KDD label mapping (official taxonomy):
  normal → normal
  DoS attacks (neptune, smurf, …)    → dos
  Probe attacks (ipsweep, nmap, …)   → probe
  R2L attacks (guess_passwd, imap, …)→ r2l
  U2R attacks (rootkit, buffer, …)   → u2r

Severity tiers:
  u2r   → CRITICAL
  r2l   → HIGH
  dos   → HIGH
  probe → POTENTIAL
  normal→ normal
"""

import os
import glob
import pandas as pd
from src.logger import get_logger

logger = get_logger(__name__)

# ── NSL-KDD attack taxonomy ────────────────────────────────────────────────
DOS_ATTACKS = frozenset({
    "back", "land", "neptune", "pod", "smurf", "teardrop",
    "apache2", "udpstorm", "processtable", "mailbomb",
})
PROBE_ATTACKS = frozenset({
    "ipsweep", "nmap", "portsweep", "satan", "mscan", "saint",
})
R2L_ATTACKS = frozenset({
    "ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy",
    "warezclient", "warezmaster", "sendmail", "named",
    "snmpgetattack", "snmpguess", "httptunnel", "xlock", "xsnoop", "worm",
})
U2R_ATTACKS = frozenset({
    "buffer_overflow", "loadmodule", "perl", "rootkit",
    "sqlattack", "xterm", "ps",
})


def map_attack_category(label: str) -> str:
    """Map a raw NSL-KDD label to its attack category."""
    if label == "normal":
        return "normal"
    if label in DOS_ATTACKS:
        return "dos"
    if label in PROBE_ATTACKS:
        return "probe"
    if label in R2L_ATTACKS:
        return "r2l"
    if label in U2R_ATTACKS:
        return "u2r"
    logger.warning(f"Unknown attack label '{label}' – mapped to 'dos'")
    return "dos"


class DatasetLoader:

    # ── NSL-KDD ──────────────────────────────────────────────────────────────

    def load_data(self, path: str, columns: list) -> pd.DataFrame:
        logger.info(f"Loading dataset ← {path}")
        df = pd.read_csv(path, names=columns)
        logger.info(f"Loaded {len(df):,} rows from {path}")
        return df

    def split_data(self, df: pd.DataFrame):
        """Return (X, y) dropping label and difficulty columns."""
        X = df.drop(["label", "difficulty"], axis=1)
        y = df["label"]
        return X, y

    def map_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """Map raw NSL-KDD labels → attack_category column."""
        df = df.copy()
        df["attack_category"] = df["label"].apply(map_attack_category)
        counts = df["attack_category"].value_counts()
        logger.info(f"Label mapping complete:\n{counts.to_string()}")
        return df

    # ── CICIDS-2017 ───────────────────────────────────────────────────────────

    def load_cicids(self, path: str) -> pd.DataFrame:
        """
        Load CICIDS-2017 CSV file(s).

        Download (Kaggle mirror):
            https://www.kaggle.com/datasets/cicdataset/cicids2017
        Place all day-CSVs in one folder, or pass a single merged CSV.

        Handles:
        - BOM / UTF-16 encoding issues from original CIC exports
        - Whitespace in column names
        - inf / NaN replacement
        """
        if os.path.isdir(path):
            files = sorted(glob.glob(os.path.join(path, "*.csv")))
            logger.info(f"CICIDS-2017: found {len(files)} CSV file(s) in {path}")
            parts = []
            for f in files:
                try:
                    chunk = pd.read_csv(f, encoding="utf-8-sig",
                                        low_memory=False, on_bad_lines="skip")
                    chunk.columns = chunk.columns.str.strip()
                    parts.append(chunk)
                    logger.info(f"  {len(chunk):,} rows ← {os.path.basename(f)}")
                except Exception as e:
                    logger.warning(f"  Skipping {os.path.basename(f)}: {e}")
            if not parts:
                raise FileNotFoundError(f"No readable CSVs in {path}")
            df = pd.concat(parts, ignore_index=True)
        else:
            logger.info(f"Loading CICIDS-2017 ← {path}")
            df = pd.read_csv(path, encoding="utf-8-sig",
                             low_memory=False, on_bad_lines="skip")
            df.columns = df.columns.str.strip()

        # Normalise label column — different CICIDS exports use different names
        label_col = None
        for candidate in ["Attack Type", "Label", " Label", "attack_type"]:
            if candidate in df.columns:
                df.rename(columns={candidate: "Attack Type"}, inplace=True)
                label_col = "Attack Type"
                break

        if label_col:
            df[label_col] = df[label_col].astype(str).str.strip()
            df.dropna(subset=[label_col], inplace=True)

        df.replace([float("inf"), float("-inf")], float("nan"), inplace=True)

        logger.info(f"CICIDS-2017 loaded: {len(df):,} rows")
        if label_col and label_col in df.columns:
            logger.info(f"Label distribution:\n{df[label_col].value_counts().to_string()}")
        return df

    # ── UNSW-NB15 ────────────────────────────────────────────────────────────

    def load_unsw(self, path: str) -> pd.DataFrame:
        """
        Load UNSW-NB15 CSV file(s).

        Download:
            https://research.unsw.edu.au/projects/unsw-nb15-dataset
        Files: UNSW_NB15_training-set.csv, UNSW_NB15_testing-set.csv

        Pass either a single file or a directory containing both.
        """
        if os.path.isdir(path):
            files = sorted(glob.glob(os.path.join(path, "*.csv")))
            logger.info(f"UNSW-NB15: found {len(files)} CSV file(s) in {path}")
            parts = [pd.read_csv(f, low_memory=False) for f in files]
            df = pd.concat(parts, ignore_index=True)
        else:
            logger.info(f"Loading UNSW-NB15 ← {path}")
            df = pd.read_csv(path, low_memory=False)

        df.columns = df.columns.str.strip()
        df.replace([float("inf"), float("-inf")], float("nan"), inplace=True)

        logger.info(f"UNSW-NB15 loaded: {len(df):,} rows")
        if "attack_cat" in df.columns:
            dist = df["attack_cat"].fillna("Normal").value_counts()
            logger.info(f"attack_cat distribution:\n{dist.to_string()}")
        return df
