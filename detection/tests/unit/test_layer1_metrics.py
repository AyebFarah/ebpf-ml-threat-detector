"""
evaluate_scores and find_best_threshold feed every number that appears
in the report. These tests use known, hand computed values so a sign
error or an off-by-one is caught immediately rather than discovered
after a training run has already produced a "final" metrics.json.
"""
import numpy as np
import pandas as pd

from detection.evaluation.metrics import evaluate_scores, find_best_threshold, flag_rate_by_group

def test_perfect_separation_gives_perfect_scores():
    y = np.array([0, 0, 0, 1, 1, 1])
    scores = np.array([0.1, 0.1, 0.2, 0.9, 0.8, 0.95])
    result = evaluate_scores(y, scores, threshold=0.5, verbose=False)
    assert result["roc_auc"] == 1.0
    assert result["pr_auc"] == 1.0
    assert result["false_positive_rate"] == 0.0
    assert result["false_negative_rate"] == 0.0


def test_single_class_returns_none_for_auc_not_a_crash():
    y = np.array([0, 0, 0, 0])
    scores = np.array([0.1, 0.2, 0.15, 0.05])
    result = evaluate_scores(y, scores, threshold=0.5, verbose=False)
    assert result["roc_auc"] is None
    assert result["pr_auc"] is None
    assert result["accuracy"] is not None  # still computable with one class


def test_all_wrong_predictions_have_zero_mcc_not_a_crash():
    """A model predicting the same class for every row makes MCC
    mathematically undefined; this must resolve to 0.0, not raise."""
    y = np.array([0, 0, 1, 1])
    scores = np.array([0.9, 0.9, 0.9, 0.9])  # predicts "attack" for everything
    result = evaluate_scores(y, scores, threshold=0.5, verbose=False)
    assert result["matthews_corrcoef"] == 0.0


def test_find_best_threshold_prefers_the_separating_threshold():
    y = np.array([0] * 50 + [1] * 50)
    scores = np.array([0.2] * 50 + [0.8] * 50)
    threshold = find_best_threshold(y, scores, metric="f1")
    assert 0.2 < threshold < 0.8


def test_find_best_threshold_single_class_falls_back_to_half_with_warning(capsys):
    y = np.array([0, 0, 0, 0])
    scores = np.array([0.1, 0.2, 0.3, 0.4])
    threshold = find_best_threshold(y, scores)
    assert threshold == 0.5
    captured = capsys.readouterr()
    assert "WARNING" in captured.out


def test_flag_rate_by_group_gives_detection_rate_per_family():
    df = pd.DataFrame({"label": [1, 1, 1, 1, 0, 0],
                       "attack_family": ["a", "a", "b", "b", None, None],
                       "scenario": ["x"] * 6})
    scores = np.array([0.9, 0.9, 0.9, 0.1, 0.1, 0.1])
    assert flag_rate_by_group(df, scores, 0.5, 1, "attack_family") == {"a": 1.0, "b": 0.5}


def test_flag_rate_by_group_gives_false_alarm_rate_per_scenario():
    df = pd.DataFrame({"label": [0, 0, 0, 0], "attack_family": [None] * 4,
                       "scenario": ["idle", "idle", "ssh_retry_storm", "ssh_retry_storm"]})
    scores = np.array([0.1, 0.1, 0.9, 0.1])
    assert flag_rate_by_group(df, scores, 0.5, 0, "scenario") == {"idle": 0.0, "ssh_retry_storm": 0.5}