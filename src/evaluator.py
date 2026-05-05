"""
src/evaluator.py – Multi-class model evaluation utilities.
"""

import numpy as np
import matplotlib.pyplot as plt

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
    auc,
    ConfusionMatrixDisplay,
)
from sklearn.preprocessing import LabelEncoder, label_binarize

from src.logger import get_logger

logger = get_logger(__name__)


class Evaluator:
    def evaluate_all(self, y_true, y_pred, multiclass: bool = True) -> dict:
        """
        Print and return classification metrics.

        Args:
            y_true:      ground-truth labels
            y_pred:      predicted labels
            multiclass:  if True use macro-averaged ROC-AUC for 5-class
        """
        report = classification_report(y_true, y_pred, zero_division=0)
        cm     = confusion_matrix(y_true, y_pred)

        logger.info("Classification Report:\n" + report)
        logger.info("Confusion Matrix:\n" + str(cm))

        # ROC-AUC – binary uses standard method; multi-class uses OvR
        try:
            if multiclass and len(set(y_true)) > 2:
                le  = LabelEncoder()
                classes = sorted(set(y_true) | set(y_pred))
                y_true_enc = le.fit_transform(y_true)
                y_pred_enc = le.transform(y_pred)
                y_true_bin = label_binarize(y_true_enc, classes=list(range(len(classes))))
                y_pred_bin = label_binarize(y_pred_enc, classes=list(range(len(classes))))
                roc = roc_auc_score(y_true_bin, y_pred_bin,
                                    average="macro", multi_class="ovr")
            else:
                le = LabelEncoder()
                roc = roc_auc_score(le.fit_transform(y_true), le.transform(y_pred))
            logger.info(f"ROC-AUC (macro OvR): {roc:.4f}")
        except Exception as exc:
            logger.warning(f"ROC-AUC could not be computed: {exc}")
            roc = None

        return {"report": report, "confusion_matrix": cm, "roc_auc": roc}

    def find_best_threshold(self, y_true_bin, y_prob) -> float:
        """
        Youden J statistic to find best binary threshold.
        y_true_bin: 0/1 encoded ground truth.
        """
        fpr, tpr, thresholds = roc_curve(y_true_bin, y_prob)
        j_scores  = tpr - fpr
        best_idx  = int(np.argmax(j_scores))
        best_t    = float(thresholds[best_idx])
        logger.info(f"Best threshold (Youden J): {best_t:.4f}")
        return best_t

    def plot_confusion_matrix(self, y_true, y_pred, save_path: str = None):
        cm      = confusion_matrix(y_true, y_pred)
        labels  = sorted(set(y_true) | set(y_pred))
        disp    = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)

        fig, ax = plt.subplots(figsize=(8, 6))
        disp.plot(ax=ax, colorbar=True, cmap="Blues")
        ax.set_title("Confusion Matrix – DeepSecure IDS")
        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches="tight")
            logger.info(f"Confusion matrix saved → {save_path}")
        else:
            plt.show()

    def plot_roc_curve(self, y_true, y_pred, save_path: str = None):
        le         = LabelEncoder()
        y_true_enc = le.fit_transform(y_true)
        y_pred_enc = le.transform(y_pred)

        fpr, tpr, _ = roc_curve(y_true_enc, y_pred_enc)
        roc_auc     = auc(fpr, tpr)

        plt.figure()
        plt.plot(fpr, tpr, label=f"ROC curve (AUC = {roc_auc:.3f})")
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.title("ROC Curve – DeepSecure IDS")
        plt.legend()

        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches="tight")
            logger.info(f"ROC curve saved → {save_path}")
        else:
            plt.show()
