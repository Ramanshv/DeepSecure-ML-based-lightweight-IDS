"""
src/feature_selector.py – Selects top-N features using a RandomForest.
"""

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from src.logger import get_logger

logger = get_logger(__name__)


class FeatureSelector:
    def select_features(self, X: pd.DataFrame, y, top_n: int = 20) -> list[str]:
        logger.info(f"Running feature selection (top {top_n}) …")
        model = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
        model.fit(X, y)
        importances = pd.Series(model.feature_importances_, index=X.columns)
        selected = importances.nlargest(top_n).index.tolist()
        logger.info(f"Selected features: {selected}")
        return selected