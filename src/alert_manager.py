"""
src/alert_manager.py – Generates, stores, and persists threat alerts.

Severity is determined by the MODEL-PREDICTED attack category:
  u2r    → CRITICAL  (privilege escalation / root compromise)
  r2l    → HIGH      (remote-to-local unauthorized access)
  dos    → HIGH      (denial-of-service flood)
  probe  → POTENTIAL (scanning / reconnaissance)
  normal → (not alerted)

Feature heuristics are kept as a fallback for live capture where the
binary (attack/normal) model is still used without category prediction.

Disposition tiers:
  CRITICAL  – immediate action required
  HIGH      – confirmed attack, log and escalate
  POTENTIAL – suspicious activity, monitor
  (LOW / normal traffic is never alerted)
"""

import pandas as pd
from datetime import datetime
from pathlib import Path

from src.logger import get_logger

logger = get_logger(__name__)

# ── Category → Severity mapping (mirrors IDS_model.CATEGORY_TO_SEVERITY) ──
CATEGORY_SEVERITY: dict[str, str] = {
    "u2r":   "CRITICAL",
    "r2l":   "HIGH",
    "dos":   "HIGH",
    "probe": "POTENTIAL",
}

# ── Heuristic fallback thresholds (live capture, no category) ─────────────
CRITICAL_SRC_BYTES   = 100_000
CRITICAL_DST_BYTES   = 100_000
HIGH_SERROR_RATE     = 0.5
HIGH_RERROR_RATE     = 0.5
HIGH_COUNT           = 100
MEDIUM_SERROR_RATE   = 0.2
MEDIUM_COUNT         = 30


from typing import Optional


def severity_from_category(category: str) -> Optional[str]:
    """
    Map a model-predicted attack category → severity string.
    Returns None for 'normal' (no alert).
    """
    return CATEGORY_SEVERITY.get(category)


def severity_from_features(features: dict, prob: float = None) -> str:
    """
    Heuristic severity fallback when attack_category is unavailable
    (e.g., live capture where model predicts binary attack/normal).
    """
    if features.get("root_shell", 0) > 0 or features.get("num_root", 0) > 0:
        return "CRITICAL"

    logged_in  = features.get("logged_in", 0)
    src_bytes  = features.get("src_bytes", 0)
    dst_bytes  = features.get("dst_bytes", 0)
    if logged_in and (src_bytes > CRITICAL_SRC_BYTES or dst_bytes > CRITICAL_DST_BYTES):
        return "CRITICAL"

    serror_rate = features.get("serror_rate", 0)
    rerror_rate = features.get("rerror_rate", 0)
    count       = features.get("count", 0)
    if serror_rate > HIGH_SERROR_RATE or rerror_rate > HIGH_RERROR_RATE or count > HIGH_COUNT:
        return "HIGH"

    if serror_rate > MEDIUM_SERROR_RATE or count > MEDIUM_COUNT:
        return "MEDIUM"

    if prob is not None and prob >= 0.95:
        return "MEDIUM"

    return "LOW"


class AlertManager:
    def __init__(self):
        self.alert_log: list[dict] = []

    # ── Public API ────────────────────────────────────────────────────────

    def generate_alert(
        self,
        predictions,
        probabilities=None,
        feature_rows: list[dict] = None,
        categories: list[str] = None,
    ) -> list[dict]:
        """
        Generate alerts for detected attacks.

        Disposition rules:
          category == 'normal'   → no alert
          category == 'probe'    → POTENTIAL
          category == 'dos'/'r2l'→ HIGH
          category == 'u2r'      → CRITICAL
          (no category provided) → feature heuristics → LOW silently dropped

        Args:
            predictions:  iterable of 'attack' / 'normal' (binary) OR
                          5-class category strings  (normal/dos/probe/r2l/u2r)
            probabilities: per-prediction max-class probability [0-1]
            feature_rows:  raw flow feature dicts (heuristic fallback)
            categories:   model-predicted attack category per sample
                          If provided, overrides feature heuristics.
        """
        alerts    = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # If 5-class predictions are passed directly as categories use them
        if categories is None and predictions is not None:
            first = next(iter(predictions), None)
            if first in CATEGORY_SEVERITY or first == "normal":
                categories = list(predictions)
                predictions = None  # disable binary path

        for i in range(len(categories) if categories else len(list(predictions or []))):
            prob = float(probabilities[i]) if probabilities is not None else None

            # ── Determine severity ────────────────────────────────────────
            if categories is not None:
                cat = categories[i]
                if cat == "normal":
                    continue           # benign → no alert
                severity = CATEGORY_SEVERITY.get(cat, "HIGH")

            else:
                # Binary prediction path (live capture fallback)
                pred = list(predictions)[i] if predictions is not None else "attack"
                if pred == "normal":
                    continue

                raw_sev  = severity_from_features(
                    feature_rows[i] if feature_rows and i < len(feature_rows) else {},
                    prob,
                )
                if raw_sev == "LOW":
                    continue           # insufficient evidence → treat as normal
                severity = "POTENTIAL" if raw_sev == "MEDIUM" else raw_sev

            alert = {
                "timestamp":  timestamp,
                "prediction": severity,
                "severity":   severity,
                "confidence": f"{prob:.2%}" if prob is not None else "N/A",
            }
            self.alert_log.append(alert)
            alerts.append(alert)

        self._log_summary(alerts, len(categories or list(predictions or [])))
        return alerts

    def get_log(self) -> list[dict]:
        return self.alert_log

    def save_log(self, path: str = "outputs/alert_log.csv"):
        if not self.alert_log:
            logger.warning("No alerts to save.")
            return

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        df = pd.DataFrame(self.alert_log)
        df.to_csv(path, index=False)
        logger.info(f"Alert log saved → {path} ({len(df)} entries)")

    # ── Private helpers ───────────────────────────────────────────────────

    @staticmethod
    def _rank_based_severity(attack_probs: list[float]) -> dict[int, str]:
        """Percentile-rank fallback ensuring a spread distribution."""
        if not attack_probs:
            return {}
        sorted_idx = sorted(range(len(attack_probs)),
                            key=lambda x: attack_probs[x], reverse=True)
        n      = len(sorted_idx)
        result = {}
        for rank, idx in enumerate(sorted_idx):
            pct = rank / n
            if pct < 0.10:
                result[idx] = "CRITICAL"
            elif pct < 0.30:
                result[idx] = "HIGH"
            elif pct < 0.60:
                result[idx] = "POTENTIAL"
            else:
                result[idx] = "LOW"
        return result

    def _log_summary(self, alerts: list[dict], total: int):
        confirmed = sum(1 for a in alerts if a["severity"] in ("HIGH", "CRITICAL"))
        potential = sum(1 for a in alerts if a["severity"] == "POTENTIAL")
        as_normal = total - len(alerts)
        logger.info(
            f"Alert summary | total={total}  confirmed={confirmed}  "
            f"potential={potential}  treated_as_normal={as_normal}"
        )
        if alerts:
            counts = {"CRITICAL": 0, "HIGH": 0, "POTENTIAL": 0}
            for a in alerts:
                counts[a["severity"]] = counts.get(a["severity"], 0) + 1
            logger.info(f"Disposition breakdown: {counts}")
            for a in alerts[-5:]:
                logger.warning(
                    f"[{a['timestamp']}] {a['severity']} – confidence {a['confidence']}"
                )