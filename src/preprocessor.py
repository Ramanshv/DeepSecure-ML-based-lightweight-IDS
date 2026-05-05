"""
src/preprocessor.py – Feature encoding for NSL-KDD data.
"""

import pandas as pd
from src.logger import get_logger

logger = get_logger(__name__)

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]


class Preprocessor:
    def encode_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """One-hot-encode categorical columns. Labels are left as-is."""
        df = df.copy()

        # Do NOT re-map the label — DatasetLoader.map_labels() already handled
        # the label column. We only encode network feature categoricals.
        existing = [c for c in CATEGORICAL_COLS if c in df.columns]
        if existing:
            df = pd.get_dummies(df, columns=existing)

        return df

    def align_features(self, train: pd.DataFrame, test: pd.DataFrame):
        """Align test columns to training columns, filling missing with 0."""
        return train.align(test, join="left", axis=1, fill_value=0)
