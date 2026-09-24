"""
Compares Layer 1 (LightGBM) against the rule-based and logistic-
regression baselines on the same held-out test split, the "ML vs
traditional detection" comparison.

Threshold handling: LightGBM's threshold is loaded from the metrics.json
train.py already tuned on its validation split. Logistic regression uses
class_weight='balanced', which has the identical calibration issue, so its threshold is
tuned here on the same validation split rather than assumed to be 0.5.
Rules emit a 0/1 prediction directly and have no threshold to tune.

Usage:
    python -m detection.layer1.evaluate --model models/layer1/model.txt
"""
from __future__ import annotations

import argparse
import json

from detection.baselines import logistic_regression, rules
from detection.data.extract import load_feature_windows
from detection.data.schema import feature_columns
from detection.data.split import group_stratified_split
from detection.evaluation.metrics import evaluate_scores, find_best_threshold
from detection.layer1 import model as layer1_model
from detection.layer1.preprocessing import prepare


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="models/layer1/model.txt")
    ap.add_argument("--metrics", default="models/layer1/metrics.json",
                    help="metrics.json produced by train.py, for the tuned LightGBM threshold")
    ap.add_argument("--entity-type", default="flow")
    args = ap.parse_args()

    df = load_feature_windows(args.entity_type)
    cols = feature_columns(df)
    df_train, df_val, df_test = group_stratified_split(df)
    if df_test.empty:
        raise SystemExit("[layer1] test split is empty -- nothing to evaluate on")

    booster = layer1_model.load(args.model)
    try:
        with open(args.metrics) as f:
            ml_threshold = json.load(f)["threshold"]
    except (FileNotFoundError, KeyError):
        print(f"[layer1] WARNING: couldn't load a tuned threshold from {args.metrics} "
              f"-- falling back to 0.5, which is likely miscalibrated for a "
              f"scale_pos_weight-trained model. Re-run train.py to produce a real one.")
        ml_threshold = 0.5
    ml_scores = booster.predict(prepare(df_test, cols))

    print(f"== Layer 1 (LightGBM, threshold={ml_threshold:.3f}) ==")
    evaluate_scores(df_test["label"].to_numpy(), ml_scores, split_name="test", threshold=ml_threshold)

    print("\n== Rule-based baseline ==")
    df_rules = rules.score_dataframe(df_test)
    evaluate_scores(df_test["label"].to_numpy(), df_rules["rule_prediction"].to_numpy(),
                    split_name="test", threshold=0.5)  # rule_prediction is already 0/1

    print("\n== Logistic regression baseline ==")
    lr_pipe = logistic_regression.train(df_train, cols)
    if not df_val.empty:
        lr_val_scores = logistic_regression.predict_proba(lr_pipe, df_val, cols)
        lr_threshold = find_best_threshold(df_val["label"].to_numpy(), lr_val_scores, metric="f1")
    else:
        print("[layer1] WARNING: val split is empty -- can't tune logistic regression's "
              f"threshold, falling back to 0.5")
        lr_threshold = 0.5
    lr_scores = logistic_regression.predict_proba(lr_pipe, df_test, cols)
    print(f"(threshold tuned on val: {lr_threshold:.3f})")
    evaluate_scores(df_test["label"].to_numpy(), lr_scores, split_name="test", threshold=lr_threshold)

    ml_preds = (ml_scores >= ml_threshold).astype(int)
    only_ml = df_test[(ml_preds == 1) & (df_rules["rule_prediction"] == 0) & (df_test.label == 1)]
    only_rules = df_test[(ml_preds == 0) & (df_rules["rule_prediction"] == 1) & (df_test.label == 1)]
    print(f"\nTrue attacks caught by ML only ({len(only_ml)}): "
          f"{only_ml['attack_family'].value_counts().to_dict()}")
    print(f"True attacks caught by rules only ({len(only_rules)}): "
          f"{only_rules['attack_family'].value_counts().to_dict()}")


if __name__ == "__main__":
    main()
