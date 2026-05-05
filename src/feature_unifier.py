"""
src/feature_unifier.py – Harmonises NSL-KDD, CICIDS-2017, and UNSW-NB15 into a
                         single common feature schema for joint training.

Column names verified against:
  - arch/cicids2017.csv          (label col = "Attack Type")
  - arch/UNSW-NB15/Training and Testing Sets/UNSW_NB15_training-set.csv
  - arch/UNSW-NB15/Training and Testing Sets/UNSW_NB15_testing-set.csv

Label taxonomy (unified):
    normal, dos, probe, r2l, u2r
"""

import pandas as pd
import numpy as np
from src.logger import get_logger

logger = get_logger(__name__)

# ── CICIDS-2017 column → NSL-KDD feature mapping ──────────────────────────────
# Verified against arch/cicids2017.csv — label column is "Attack Type"
CICIDS_TO_NSL = {
    "Flow Duration":                "duration",
    "Total Fwd Packets":            "count",
    "Total Backward Packets":       "srv_count",
    "Total Length of Fwd Packets":  "src_bytes",
    "Total Length of Bwd Packets":  "dst_bytes",
    "Fwd Packet Length Max":        "hot",
    "Flow Packets/s":               "dst_host_same_src_port_rate",
    "Fwd PSH Flags":                "urgent",
    "SYN Flag Count":               "syn_count",
    "RST Flag Count":               "rst_count",
    "FIN Flag Count":               "fin_count",
    "ACK Flag Count":               "ack_count",
    "URG Flag Count":               "urg_count",
    "Idle Mean":                    "srv_serror_rate",
    "Protocol":                     "_protocol_int",
    "Destination Port":             "_dst_port",
    "Attack Type":                  "raw_label",   # ← actual column in this CSV
}

CICIDS_LABEL_MAP = {
    # Benign
    "Normal Traffic":               "normal",
    "BENIGN":                       "normal",
    # DoS / DDoS  — both short aggregate and full day-file names
    "DoS":                          "dos",
    "DDoS":                         "dos",
    "DoS slowloris":                "dos",
    "DoS Slowhttptest":             "dos",
    "DoS Hulk":                     "dos",
    "DoS GoldenEye":                "dos",
    "Heartbleed":                   "dos",
    "DDOS attack-HOIC":             "dos",
    "DDOS attack-LOIC-UDP":         "dos",
    "DoS attacks-Hulk":             "dos",
    "DoS attacks-GoldenEye":        "dos",
    "DoS attacks-Slowloris":        "dos",
    "DoS attacks-SlowHTTPTest":     "dos",
    # Probe / Scanning
    "Port Scanning":                "probe",
    "PortScan":                     "probe",
    "FTP-BruteForce":               "probe",
    "SSH-Bruteforce":               "probe",
    # R2L (credential / web / bot attacks)
    "Brute Force":                  "r2l",
    "Brute Force -Web":             "r2l",
    "Brute Force -XSS":             "r2l",
    "Web Attacks":                  "r2l",
    "Web Attack":                   "r2l",
    "Web Attack - Brute Force":     "r2l",
    "Web Attack \u2013 Brute Force":     "r2l",
    "Web Attack \x96 Brute Force":   "r2l",
    "Web Attack - XSS":             "r2l",
    "Web Attack \u2013 XSS":             "r2l",
    "Web Attack - Sql Injection":   "r2l",
    "Web Attack \u2013 Sql Injection":   "r2l",
    "SQL Injection":                "r2l",
    "Bots":                         "r2l",
    "Bot":                          "r2l",
    "FTP-Patator":                  "r2l",
    "SSH-Patator":                  "r2l",
    "Infiltration":                 "r2l",
    # U2R
    "Shellcode":                    "u2r",
}


# ── UNSW-NB15 column → NSL-KDD feature mapping ───────────────────────────────
# Verified against UNSW_NB15_training-set.csv (has proper headers + attack_cat)
UNSW_TO_NSL = {
    "dur":              "duration",
    "proto":            "protocol_type",
    "service":          "service",
    "state":            "flag",
    "sbytes":           "src_bytes",
    "dbytes":           "dst_bytes",
    "ct_srv_src":       "count",
    "ct_srv_dst":       "srv_count",
    "sload":            "hot",
    "dload":            "dst_host_same_src_port_rate",
    "is_sm_ips_ports":  "land",
    "ct_flw_http_mthd": "logged_in",
    "sinpkt":           "serror_rate",
    "dinpkt":           "rerror_rate",
    "ct_dst_ltm":       "dst_host_count",
    "ct_src_ltm":       "dst_host_srv_count",
    # label
    "attack_cat":       "raw_label",
    "label":            "_binary_label",   # ignored — we use attack_cat
}

UNSW_LABEL_MAP = {
    "Normal":           "normal",
    "Generic":          "dos",
    "Exploits":         "r2l",
    "Fuzzers":          "probe",
    "Dos":              "dos",
    "DoS":              "dos",
    "Reconnaissance":   "probe",
    "Analysis":         "probe",
    "Backdoor":         "r2l",
    "Shellcode":        "u2r",
    "Worms":            "u2r",
    "":                 "normal",
}

# ── Common schema ─────────────────────────────────────────────────────────────
COMMON_FEATURES = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "count", "srv_count",
    "serror_rate", "rerror_rate", "srv_serror_rate", "same_srv_rate",
    "diff_srv_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_serror_rate", "dst_host_rerror_rate",
    "attack_category",
]


def _harmonise_cicids(df: pd.DataFrame) -> pd.DataFrame:
    """Map CICIDS-2017 columns to NSL-KDD feature names and label taxonomy."""
    logger.info("Harmonising CICIDS-2017 …")
    rename = {k: v for k, v in CICIDS_TO_NSL.items()
              if k in df.columns and v not in ("_ignore",)}
    out = df.rename(columns=rename).copy()

    # Protocol int → string
    if "_protocol_int" in out.columns:
        out["protocol_type"] = out["_protocol_int"].map(
            {6: "tcp", 17: "udp", 1: "icmp"}
        ).fillna("other")
        out.drop(columns=["_protocol_int"], inplace=True)
    else:
        out["protocol_type"] = "tcp"

    # Service from dst port
    if "_dst_port" in out.columns:
        from src.flow_extractor import COMMON_PORTS
        out["service"] = out["_dst_port"].astype(str).map(COMMON_PORTS).fillna("other")
        out.drop(columns=["_dst_port"], inplace=True)
    else:
        out["service"] = "other"

    # Label
    if "raw_label" in out.columns:
        out["attack_category"] = out["raw_label"].map(
            lambda x: CICIDS_LABEL_MAP.get(str(x).strip(), "dos")
        )
    else:
        out["attack_category"] = "normal"

    # Duration: CICIDS stores microseconds → convert to seconds
    if "duration" in out.columns:
        out["duration"] = pd.to_numeric(out["duration"], errors="coerce").fillna(0) / 1_000_000.0

    # Fill missing NSL-KDD cols
    for col in COMMON_FEATURES:
        if col not in out.columns:
            out[col] = 0

    out["flag"]           = "OTH"
    out["wrong_fragment"] = 0
    out["land"]           = 0

    # Derive rates from raw flag counters
    pkt_total = (
        pd.to_numeric(out.get("count", pd.Series([1])), errors="coerce").fillna(1) +
        pd.to_numeric(out.get("srv_count", pd.Series([0])), errors="coerce").fillna(0)
    ).clip(lower=1)

    if "syn_count" in out.columns:
        syn = pd.to_numeric(out["syn_count"], errors="coerce").fillna(0)
        out["serror_rate"]     = (syn / pkt_total).clip(0, 1)
        out["srv_serror_rate"] = out["serror_rate"]
    if "rst_count" in out.columns:
        rst = pd.to_numeric(out["rst_count"], errors="coerce").fillna(0)
        out["rerror_rate"] = (rst / pkt_total).clip(0, 1)

    out["same_srv_rate"]          = 0.5
    out["diff_srv_rate"]          = 0.5
    out["dst_host_count"]         = 100
    out["dst_host_srv_count"]     = 50
    out["dst_host_same_srv_rate"] = 0.5
    out["dst_host_diff_srv_rate"] = 0.5
    out["dst_host_serror_rate"]   = out.get("serror_rate", pd.Series([0]))
    out["dst_host_rerror_rate"]   = out.get("rerror_rate", pd.Series([0]))

    return out[COMMON_FEATURES]


def _harmonise_unsw(df: pd.DataFrame) -> pd.DataFrame:
    """Map UNSW-NB15 columns to NSL-KDD feature names and label taxonomy."""
    logger.info("Harmonising UNSW-NB15 …")
    rename = {k: v for k, v in UNSW_TO_NSL.items()
              if k in df.columns and v not in ("_ignore", "_binary_label")}
    out = df.rename(columns=rename).copy()

    # Label from attack_cat
    if "raw_label" in out.columns:
        out["attack_category"] = out["raw_label"].fillna("Normal").map(
            lambda x: UNSW_LABEL_MAP.get(str(x).strip().title(),
                      UNSW_LABEL_MAP.get(str(x).strip(), "r2l"))
        )
    else:
        out["attack_category"] = "normal"

    # Fill missing NSL-KDD cols
    for col in COMMON_FEATURES:
        if col not in out.columns:
            out[col] = 0

    # UNSW 'state' maps to NSL-KDD 'flag' (FIN→SF, CON→SF, REJ→REJ, etc.)
    if "flag" in out.columns:
        state_map = {"FIN": "SF", "CON": "SF", "REJ": "REJ",
                     "RST": "RSTO", "INT": "S1", "CLO": "SF"}
        out["flag"] = out["flag"].map(state_map).fillna("OTH")

    out["wrong_fragment"] = 0

    out["same_srv_rate"]          = 0.5
    out["diff_srv_rate"]          = 0.5
    out["dst_host_same_srv_rate"] = 0.5
    out["dst_host_diff_srv_rate"] = 0.5

    if "serror_rate" in out.columns:
        out["dst_host_serror_rate"] = pd.to_numeric(
            out["serror_rate"], errors="coerce").fillna(0)
    if "rerror_rate" in out.columns:
        out["dst_host_rerror_rate"] = pd.to_numeric(
            out["rerror_rate"], errors="coerce").fillna(0)

    out["srv_serror_rate"] = out.get("dst_host_serror_rate", 0)

    return out[COMMON_FEATURES]


def _harmonise_nsl(df: pd.DataFrame) -> pd.DataFrame:
    """NSL-KDD is already in the native schema — just select common columns."""
    out = df.copy()
    for col in COMMON_FEATURES:
        if col not in out.columns:
            out[col] = 0
    return out[COMMON_FEATURES]


def unify_datasets(
    nsl_df:    pd.DataFrame,
    cicids_df: "pd.DataFrame | None" = None,
    unsw_df:   "pd.DataFrame | None" = None,
) -> pd.DataFrame:
    """
    Combine NSL-KDD with optional CICIDS-2017 and/or UNSW-NB15.

    All datasets are mapped to the COMMON_FEATURES schema. The combined
    DataFrame can be passed directly to IDSModel.train_and_compare().

    Returns:
        Unified DataFrame with `attack_category` label column.
    """
    parts = [_harmonise_nsl(nsl_df)]
    logger.info(f"NSL-KDD rows: {len(nsl_df):,}")

    if cicids_df is not None and not cicids_df.empty:
        c = _harmonise_cicids(cicids_df)
        parts.append(c)
        logger.info(f"CICIDS-2017 rows added: {len(c):,}")

    if unsw_df is not None and not unsw_df.empty:
        u = _harmonise_unsw(unsw_df)
        parts.append(u)
        logger.info(f"UNSW-NB15 rows added: {len(u):,}")

    combined = pd.concat(parts, ignore_index=True)

    # Clip extreme byte values and fill NaNs
    for col in ["src_bytes", "dst_bytes", "hot", "duration"]:
        if col in combined.columns:
            combined[col] = pd.to_numeric(
                combined[col], errors="coerce"
            ).clip(upper=1e9).fillna(0)

    num_cols = combined.select_dtypes(include="number").columns
    combined[num_cols] = combined[num_cols].fillna(0)

    dist = combined["attack_category"].value_counts().to_dict()
    logger.info(f"Unified dataset: {len(combined):,} rows | classes: {dist}")

    return combined
