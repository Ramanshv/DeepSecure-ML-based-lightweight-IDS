"""
src/IDS_model.py – Multi-class attack category classifier for DeepSecure IDS.

The model predicts 5 classes:
  normal  – benign traffic
  dos     – Denial-of-Service attacks  (maps to HIGH severity)
  probe   – Scanning / reconnaissance  (maps to POTENTIAL)
  r2l     – Remote-to-Local attacks    (maps to HIGH severity)
  u2r     – User-to-Root / privilege   (maps to CRITICAL severity)

Model selection:
  - Compares RF, XGBoost, and Logistic Regression via 5-fold CV
  - Automatically picks the best F1-macro scorer (usually XGBoost)
  - Applies sigmoid calibration (cv='prefit') for realistic probabilities

Class imbalance handling:
  - class_weight='balanced' in RF
  - Inverse-frequency sample weights in XGBoost
  - Both force the model to learn rare U2R and R2L patterns
"""

import pandas as pd
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.utils import resample
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.calibration import CalibratedClassifierCV
from xgboost import XGBClassifier

from src.logger import get_logger

logger = get_logger(__name__)

# Attack category → severity tier mapping (used by alert_manager / app.py)
CATEGORY_TO_SEVERITY: dict[str, str] = {
    "normal": "normal",
    "probe":  "POTENTIAL",   # scanning/recon → suspicious but unconfirmed
    "dos":    "HIGH",        # denial-of-service → confirmed attack
    "r2l":    "HIGH",        # remote-to-local → confirmed attack
    "u2r":    "CRITICAL",    # privilege escalation / root compromise → critical
}


class _XGBWrapper:
    """
    Thin wrapper so integer-label XGBClassifier behaves as a string-label
    sklearn estimator — required for CalibratedClassifierCV.
    """
    _estimator_type = "classifier"   # ← tells sklearn this IS a classifier

    def __init__(self, xgb_model, label_encoder):
        self._model   = xgb_model
        self._le      = label_encoder
        self.classes_ = label_encoder.classes_  # string class names

    def fit(self, X, y, sample_weight=None):
        return self    # model is already fitted; calibrator calls this but we skip

    def predict(self, X):
        int_preds = self._model.predict(X)
        return self._le.inverse_transform(int_preds.astype(int))

    def predict_proba(self, X):
        return self._model.predict_proba(X)

    def get_params(self, deep=True):
        return {}

    def set_params(self, **params):
        return self


class IDSModel:
    def __init__(self):
        self.model = None
        self.le    = LabelEncoder()

    # ── Training ──────────────────────────────────────────────────────────

    def train_and_compare(self, X: pd.DataFrame, y: pd.Series) -> pd.DataFrame:
        """
        Train multiple classifiers, compare via cross-validation, then
        calibrate and store the best scorer as the final model.

        Args:
            X: feature matrix (preprocessed, selected features)
            y: attack_category labels  (normal / dos / probe / r2l / u2r)
        """
        logger.info(f"Training on {len(X):,} samples | classes: {sorted(y.unique())}")

        class_counts = y.value_counts()
        logger.info(f"Class distribution:\n{class_counts.to_string()}")

        # XGBoost requires integer-encoded labels
        y_enc = self.le.fit_transform(y)

        # Inverse-frequency sample weights: rare classes (U2R/R2L) get boosted
        freq       = y.map(class_counts)
        sample_wts = (1.0 / freq).values
        sample_wts /= sample_wts.mean()   # normalise so mean = 1

        X_sample, y_sample = resample(
            X, y, n_samples=min(20_000, len(X)), random_state=42, stratify=y
        )

        # (model_object, X_train, y_train, sample_weights_or_None)
        model_configs = {
            "Random Forest": (
                RandomForestClassifier(
                    n_estimators=200,
                    max_depth=20,
                    min_samples_split=3,
                    min_samples_leaf=1,
                    class_weight="balanced",
                    random_state=42,
                    n_jobs=-1,
                ),
                X, y, None,
            ),
            "XGBoost": (
                XGBClassifier(
                    n_estimators=300,
                    max_depth=8,
                    learning_rate=0.08,
                    min_child_weight=1,
                    subsample=0.85,
                    colsample_bytree=0.85,
                    eval_metric="mlogloss",
                    use_label_encoder=False,
                    random_state=42,
                    verbosity=0,
                    n_jobs=-1,
                ),
                X, y_enc, sample_wts,     # per-sample weights boost rare classes
            ),
            "Logistic Regression": (
                make_pipeline(
                    StandardScaler(),
                    LogisticRegression(
                        max_iter=2000,
                        class_weight="balanced",
                        random_state=42,
                        solver="lbfgs",   # multinomial is default in sklearn >= 1.5
                    ),
                ),
                X_sample, y_sample, None,
            ),
        }

        cv      = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        results = []
        fitted  = {}

        for name, (mdl, X_tr, y_tr, wts) in model_configs.items():
            logger.info(f"Training {name} …")
            scores = cross_val_score(mdl, X_tr, y_tr, cv=cv, scoring="f1_macro", n_jobs=-1)
            if wts is not None:
                mdl.fit(X_tr, y_tr, sample_weight=wts)
            else:
                mdl.fit(X_tr, y_tr)

            fitted[name] = mdl
            results.append({
                "Model":       name,
                "CV F1 Macro": round(scores.mean(), 4),
                "CV F1 Std":   round(scores.std(),  4),
            })
            logger.info(f"{name}: CV F1-macro = {scores.mean():.4f} ± {scores.std():.4f}")

        df = pd.DataFrame(results).sort_values("CV F1 Macro", ascending=False)
        logger.info("Model comparison:\n" + df.to_string(index=False))

        # ── Auto-select best model by CV score, then calibrate ────────────
        best_name = df.iloc[0]["Model"]
        best_raw  = fitted[best_name]
        logger.info(f"Best model: {best_name} — calibrating with sigmoid …")

        # XGBoost outputs integer labels; wrap so predict() returns strings
        if best_name == "XGBoost":
            best_raw = _XGBWrapper(best_raw, self.le)

        # cv='prefit' is deprecated in sklearn 1.6. Use FrozenEstimator if available.
        try:
            from sklearn.frozen import FrozenEstimator
            calibrated = CalibratedClassifierCV(FrozenEstimator(best_raw), method="sigmoid")
            calibrated.fit(X, y)
        except ImportError:
            # Fallback for sklearn < 1.6
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                calibrated = CalibratedClassifierCV(best_raw, method="sigmoid", cv="prefit")
                calibrated.fit(X, y)
        self.model = calibrated

        logger.info(f"Final model classes: {list(self.model.classes_)}")
        return df

    # ── Inference ─────────────────────────────────────────────────────────

    def predict(self, X) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X) -> np.ndarray:
        return self.model.predict_proba(X)

    def predict_severity(self, X) -> list[str]:
        """Return a severity tier for each sample."""
        categories = self.predict(X)
        return [CATEGORY_TO_SEVERITY.get(c, "HIGH") for c in categories]

    @property
    def classes_(self):
        return self.model.classes_

    # ── Persistence ───────────────────────────────────────────────────────

    def save_model(self, path: str):
        joblib.dump(self.model, path)
        logger.info(f"Model saved → {path}")

    def load_model(self, path: str):
        self.model = joblib.load(path)
        logger.info(f"Model loaded ← {path}")

    def save_class_map(self, path: str):
        import json
        mapping = {c: i for i, c in enumerate(self.model.classes_)}
        with open(path, "w") as f:
            json.dump(mapping, f, indent=2)
        logger.info(f"Class map saved → {path}")