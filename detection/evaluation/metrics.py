"""
Shared metric computation -- used by layer1/train.py, layer1/evaluate.py,
and (once they exist) layer2's equivalents, so "how do we score a split"
is defined exactly once instead of drifting between modules.
"""
from __future__ import annotations
import time
import numpy as np
from sklearn.metrics import (
    average_precision_score, classification_report, confusion_matrix, f1_score, roc_auc_score,
)


def find_best_threshold(y, scores, metric: str = "f1") -> float:
    """Scans candidate thresholds and returns the one maximizing `metric`
    on (y, scores). ALWAYS call this on a validation split, never on
    test, tuning on test would leak test information into the
    decision boundary.

    This exists because a training objective that reweights classes
    (scale_pos_weight, class_weight='balanced') changes what
    predict_proba's output means. A model can have perfect ROC-AUC
    (perfectly ranks attack above benign) and still call every single
    row "benign" at threshold 0.5, because reweighting the loss shifts
    where the decision boundary actually sits, 0.5 was never
    guaranteed to be it. Skipping this step and hardcoding 0.5 anywhere
    downstream of a reweighted classifier silently discards recall.
    """
    y = np.asarray(y)
    if len(set(y)) < 2:
        print(f"[metrics] WARNING: find_best_threshold got single-class data ({len(y)} rows) "
              f"-- can't tune a decision boundary without both classes present in val. "
              f"Falling back to 0.5: this usually means val ended up too small or "
              f"category-imbalanced -- check the split.")
        return 0.5

    thresholds = np.linspace(0.01, 0.99, 99)
    best_t, best_score = 0.5, -1.0
    for t in thresholds:
        preds = (scores >= t).astype(int)
        if metric == "f1":
            s = f1_score(y, preds, zero_division=0)
        elif metric == "youden":
            tn, fp, fn, tp = confusion_matrix(y, preds, labels=[0, 1]).ravel()
            tpr = tp / (tp + fn) if (tp + fn) else 0
            fpr = fp / (fp + tn) if (fp + tn) else 0
            s = tpr - fpr
        else:
            raise ValueError(f"unknown metric: {metric}")
        if s > best_score:
            best_score, best_t = s, t
    return float(best_t)


def evaluate_scores(y, scores, split_name: str = "", threshold: float = 0.5, verbose: bool = True) -> dict:
    preds = (scores >= threshold).astype(int)

    result: dict = {}
    if verbose:
        print(f"\n== {split_name} ({len(y)} rows) ==")
    if len(set(y)) < 2:
        result["roc_auc"] = None
        result["pr_auc"] = None
        if verbose:
            print("(only one class present -- AUC undefined)")
    else:
        result["roc_auc"] = roc_auc_score(y, scores)
        result["pr_auc"] = average_precision_score(y, scores)
        if verbose:
            print(f"ROC-AUC: {result['roc_auc']:.4f}")
            print(f"PR-AUC:  {result['pr_auc']:.4f}")

    if verbose:
        print(classification_report(y, preds, target_names=["benign", "attack"], zero_division=0))
        print("confusion matrix [[TN, FP], [FN, TP]]:")
        print(confusion_matrix(y, preds))

    result["confusion_matrix"] = confusion_matrix(y, preds).tolist()
    return result


def timed_predict(predict_fn, X):
    """Runs predict_fn(X) once, returning (scores, ms_per_row)."""
    t0 = time.perf_counter()
    scores = predict_fn(X)
    ms_per_row = (time.perf_counter() - t0) * 1000 / max(len(X), 1)
    return scores, ms_per_row
