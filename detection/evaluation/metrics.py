"""
Shared metric computation, used by training, evaluation, and
generalization testing, so how a split is scored is defined exactly
once instead of drifting between modules.

Metrics reported at test time, and why each one is here:

  roc_auc, pr_auc   : threshold independent ranking quality. PR AUC is
                      the more informative of the two under class
                      imbalance (few attack rows among many benign
                      rows), since ROC AUC can look good even when
                      precision is poor.
  log_loss          : how well calibrated the predicted probabilities
                      are, not just whether the final label was right.
  accuracy          : kept for context only, misleading on its own when
                      classes are imbalanced.
  balanced_accuracy : the average of recall on each class separately,
                      the imbalance corrected version of accuracy.
  precision, recall, f1 : the standard operating point trio at the
                      tuned decision threshold.
  false_positive_rate, false_negative_rate : the two operational costs
                      of a live detector, alert fatigue versus missed
                      attacks, reported directly rather than only
                      implied by precision and recall.
  matthews_corrcoef : one summary number, from minus 1 to plus 1, that
                      stays meaningful under heavy class imbalance,
                      unlike accuracy or F1 alone.
"""
from __future__ import annotations

import time

import numpy as np
from sklearn.metrics import (
    accuracy_score, average_precision_score, balanced_accuracy_score,
    classification_report, confusion_matrix, f1_score, log_loss,
    matthews_corrcoef, precision_score, recall_score, roc_auc_score,
)


def find_best_threshold(y, scores, metric: str = "f1") -> float:
    """Scans candidate thresholds and returns the one maximizing `metric`
    on (y, scores). Always call this on a validation split, never on
    test, tuning on test would leak test information into the decision
    boundary.

    This exists because a training objective that reweights classes
    (scale_pos_weight, class_weight="balanced") changes what
    predict_proba's output means. A model can have perfect ROC AUC
    (perfectly ranks attack above benign) and still call every row
    "benign" at threshold 0.5, because reweighting the loss shifts
    where the decision boundary actually sits, 0.5 was never
    guaranteed to be it.
    """
    y = np.asarray(y)
    if len(set(y)) < 2:
        print(f"[metrics] WARNING: find_best_threshold got single class data ({len(y)} rows), "
              f"can't tune a decision boundary without both classes present in val. "
              f"Falling back to 0.5, check the split.")
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
        elif metric == "mcc":
            s = matthews_corrcoef(y, preds) if len(set(preds)) > 1 else -1.0
        else:
            raise ValueError(f"unknown metric: {metric}")
        if s > best_score:
            best_score, best_t = s, t
    return float(best_t)


def evaluate_scores(y, scores, split_name: str = "", threshold: float = 0.5, verbose: bool = True) -> dict:
    y = np.asarray(y)
    scores = np.asarray(scores, dtype=float)
    preds = (scores >= threshold).astype(int)

    result: dict = {}
    if verbose:
        print(f"\n== {split_name} ({len(y)} rows) ==")

    if len(set(y)) < 2:
        result["roc_auc"] = None
        result["pr_auc"] = None
        result["log_loss"] = None
        if verbose:
            print("(only one class present, ROC AUC / PR AUC / log loss undefined)")
    else:
        result["roc_auc"] = roc_auc_score(y, scores)
        result["pr_auc"] = average_precision_score(y, scores)
        clipped = np.clip(scores, 1e-7, 1 - 1e-7)
        result["log_loss"] = log_loss(y, clipped, labels=[0, 1])
        if verbose:
            print(f"ROC AUC : {result['roc_auc']:.4f}")
            print(f"PR AUC  : {result['pr_auc']:.4f}")
            print(f"Log loss: {result['log_loss']:.4f}")

    result["accuracy"] = float(accuracy_score(y, preds))
    result["balanced_accuracy"] = float(balanced_accuracy_score(y, preds))
    result["precision"] = float(precision_score(y, preds, zero_division=0))
    result["recall"] = float(recall_score(y, preds, zero_division=0))
    result["f1"] = float(f1_score(y, preds, zero_division=0))
    result["matthews_corrcoef"] = float(matthews_corrcoef(y, preds)) if len(set(preds)) > 1 else 0.0

    tn, fp, fn, tp = confusion_matrix(y, preds, labels=[0, 1]).ravel()
    result["false_positive_rate"] = float(fp / (fp + tn)) if (fp + tn) else 0.0
    result["false_negative_rate"] = float(fn / (fn + tp)) if (fn + tp) else 0.0
    result["true_positive_rate"] = float(tp / (tp + fn)) if (tp + fn) else 0.0
    result["true_negative_rate"] = float(tn / (tn + fp)) if (tn + fp) else 0.0

    if verbose:
        print(f"Accuracy: {result['accuracy']:.4f}   Balanced accuracy: {result['balanced_accuracy']:.4f}")
        print(f"Precision: {result['precision']:.4f}   Recall: {result['recall']:.4f}   "
              f"F1: {result['f1']:.4f}")
        print(f"False positive rate: {result['false_positive_rate']:.4f}   "
              f"False negative rate: {result['false_negative_rate']:.4f}")
        print(f"Matthews correlation coefficient: {result['matthews_corrcoef']:.4f}")
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

def flag_rate_by_group(df, scores, threshold: float, label_value: int, group_col: str) -> dict:
    """Fraction of windows flagged as attack, per group, among rows with the given label.
    label_value=1 with group_col='attack_family' gives detection rate per attack.
    label_value=0 with group_col='scenario' gives false positive rate per benign scenario."""
    part = df.assign(_flagged=(np.asarray(scores) >= threshold).astype(int))
    part = part[part["label"] == label_value]
    return part.groupby(group_col)["_flagged"].mean().round(4).to_dict()