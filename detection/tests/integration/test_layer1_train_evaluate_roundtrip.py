"""
Slower than the unit tests: trains a real LightGBM model on synthetic data and checks
train, save, load and score. Run before a demo or before final report numbers.
"""
import numpy as np
import pandas as pd
import pytest

pytest.importorskip("lightgbm")

import detection.algorithms  # noqa: F401
from detection import artifacts
from detection.core.preprocessing import prepare
from detection.core.registry import get_model_class
from detection.data.split import group_stratified_split


def _synthetic_feature_windows(n_runs=12, rows_per_run=40, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for run_id in range(n_runs):
        label = run_id % 2
        base = 5.0 if label else 1.0
        for _ in range(rows_per_run):
            rows.append({"run_id": run_id, "label": label,
                         "scenario": "attack" if label else "benign",
                         "feat_a": rng.normal(base, 1.0), "feat_b": rng.normal(base * 2, 1.0)})
    return pd.DataFrame(rows)


@pytest.mark.integration
def test_lightgbm_train_save_load_score(models_dir):
    from sklearn.metrics import roc_auc_score

    df = _synthetic_feature_windows()
    cols = ["feat_a", "feat_b"]
    df_train, df_val, df_test = group_stratified_split(df, seed=1, verbose=False)

    model = get_model_class("lightgbm")()
    model.fit(prepare(df_train, cols), df_train["label"], prepare(df_val, cols), df_val["label"])
    artifacts.save_bundle("host", "lightgbm", "test_run", model, cols, 0.5, {}, None, "synthetic",
                          {"test_run_ids": sorted(int(r) for r in df_test.run_id.unique())})

    bundle = artifacts.load_bundle("host", "lightgbm", "test_run")
    scores = bundle.model.predict_proba(prepare(df_test, bundle.feature_cols))

    assert len(scores) == len(df_test)
    assert 0.0 <= scores.min() and scores.max() <= 1.0
    assert roc_auc_score(df_test["label"], scores) > 0.8