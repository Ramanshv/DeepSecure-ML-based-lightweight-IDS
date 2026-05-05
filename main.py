"""
main.py – Training pipeline for DeepSecure IDS.

Training data:
  - REQUIRED: NSL-KDD (KDDTrain+ / KDDTest+ / KDDTest-21)
  - OPTIONAL: CICIDS-2017 → set CICIDS_PATH env var (file or folder)
  - OPTIONAL: UNSW-NB15  → set UNSW_PATH env var  (file or folder)

Validation: KDDTest-21  (attacks the model has never seen — honest holdout)
Test:       KDDTest+    (broader set with novel variants)

Run:
    python3 main.py

    # With extra datasets:
    CICIDS_PATH=/path/to/cicids python3 main.py
    UNSW_PATH=/path/to/unsw     python3 main.py
"""

import os
from collections import Counter

import numpy as np
import pandas as pd

import config
from src.logger           import get_logger
from src.dataset_loader   import DatasetLoader
from src.preprocessor     import Preprocessor
from src.feature_selector import FeatureSelector
from src.IDS_model         import IDSModel, CATEGORY_TO_SEVERITY
from src.evaluator         import Evaluator
from src.alert_manager     import AlertManager
from src.feature_unifier   import unify_datasets

logger = get_logger("main")


def _prep_features(df: pd.DataFrame, selected_features: list) -> pd.DataFrame:
    """Drop metadata columns, align to selected features, fill missing with 0."""
    X = df.drop(["label", "difficulty", "attack_category"], axis=1, errors="ignore")
    for col in selected_features:
        if col not in X.columns:
            X[col] = 0
    return X[selected_features]


def run():
    logger.info("===== DeepSecure IDS – Multi-Class Training Pipeline =====")

    loader = DatasetLoader()
    pre    = Preprocessor()

    # ── Load NSL-KDD splits ───────────────────────────────────────────────
    train_raw = loader.load_data(config.TRAIN_PATH,      config.COLUMNS)
    test_raw  = loader.load_data(config.TEST_PATH,       config.COLUMNS)
    val_raw   = loader.load_data(config.VALIDATION_PATH, config.COLUMNS)

    train_raw = loader.map_labels(train_raw)
    test_raw  = loader.map_labels(test_raw)
    val_raw   = loader.map_labels(val_raw)

    train_raw["label"] = train_raw["attack_category"]
    test_raw["label"]  = test_raw["attack_category"]
    val_raw["label"]   = val_raw["attack_category"]

    # ── Encode features (one-hot categoricals) — fit on ALL data ─────────
    combined = pd.concat([train_raw, test_raw, val_raw], keys=["train", "test", "val"])
    combined = pre.encode_features(combined)

    train = combined.xs("train")
    test  = combined.xs("test")
    val   = combined.xs("val")

    # ── Feature Selection (on NSL-KDD only, for clean signal) ────────────
    X_full = train.drop(["label", "difficulty", "attack_category"], axis=1, errors="ignore")
    y_cat  = train["label"]
    y_bin  = (y_cat != "normal").astype(int)

    fs = FeatureSelector()
    selected_features = fs.select_features(X_full, y_bin, top_n=35)
    X_full = X_full[selected_features]

    # (features file written later, after optional dataset unification)

    # ── Optionally load and merge extra datasets ──────────────────────────
    cicids_df = None
    unsw_df   = None

    if config.CICIDS_PATH:
        logger.info(f"Extra dataset: CICIDS-2017 ← {config.CICIDS_PATH}")
        try:
            cicids_df = loader.load_cicids(config.CICIDS_PATH)
        except Exception as e:
            logger.error(f"Failed to load CICIDS-2017: {e}")

    if config.UNSW_PATH:
        logger.info(f"Extra dataset: UNSW-NB15 ← {config.UNSW_PATH}")
        try:
            unsw_df = loader.load_unsw(config.UNSW_PATH)
        except Exception as e:
            logger.error(f"Failed to load UNSW-NB15: {e}")

    if cicids_df is not None or unsw_df is not None:
        # Harmonise all datasets into the common feature schema
        # then limit training X to features that exist in the unified schema
        unified = unify_datasets(train, cicids_df=cicids_df, unsw_df=unsw_df)

        # After unification, re-run feature selection on the merged data
        # using only features that are available in ALL sets
        common_cols = [c for c in selected_features if c in unified.columns]
        logger.info(f"Using {len(common_cols)} features available across all datasets")

        X_train = unified[common_cols].fillna(0)
        y_train = unified["attack_category"]
        selected_features = common_cols   # update for test/val alignment
    else:
        logger.info("Training on NSL-KDD only (set CICIDS_PATH/UNSW_PATH to expand)")
        X_train = X_full
        y_train = y_cat

    # ── Save the FINAL feature list (after unification may have reduced it) ──
    os.makedirs(os.path.dirname(config.FEATURES_PATH), exist_ok=True)
    with open(config.FEATURES_PATH, "w") as f:
        f.write("\n".join(selected_features))
    logger.info(f"Selected features saved → {config.FEATURES_PATH} ({len(selected_features)} features)")

    # ── Train on FULL training set ────────────────────────────────────────
    ids = IDSModel()
    ids.train_and_compare(X_train, y_train)
    ids.save_model(config.MODEL_PATH)
    ids.save_class_map(config.MODEL_PATH.replace(".pkl", "_classes.json"))

    evaluator = Evaluator()

    # ── Validation: KDDTest-21 ────────────────────────────────────────────
    logger.info("===== Validation Results (KDDTest-21 — unseen attack types) =====")
    X_val = _prep_features(val, selected_features)
    y_val = val["label"]
    evaluator.evaluate_all(y_val, ids.predict(X_val), multiclass=True)

    # ── Test: KDDTest+ ────────────────────────────────────────────────────
    logger.info("===== Test Results (KDDTest+ — novel variants) =====")
    X_test       = _prep_features(test, selected_features)
    y_test       = test["label"]
    y_test_pred  = ids.predict(X_test)
    y_test_proba = ids.predict_proba(X_test).max(axis=1)

    evaluator.evaluate_all(y_test, y_test_pred, multiclass=True)

    # ── Severity Distribution ─────────────────────────────────────────────
    logger.info("===== Severity Distribution (test set) =====")
    severities = [CATEGORY_TO_SEVERITY.get(c, "HIGH") for c in y_test_pred]
    for sev, count in sorted(Counter(severities).items()):
        logger.info(f"  {sev:10s}: {count:,}")

    # ── Alerts ────────────────────────────────────────────────────────────
    alerts = AlertManager()
    alerts.generate_alert(
        predictions=None,
        probabilities=y_test_proba.tolist(),
        categories=y_test_pred.tolist(),
    )
    alerts.save_log(config.ALERT_LOG_PATH)

    logger.info("===== Training + Evaluation Complete =====")


if __name__ == "__main__":
    run()