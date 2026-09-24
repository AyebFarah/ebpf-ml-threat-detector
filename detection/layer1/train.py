"""
Layer 1 training entrypoint. Loads flow-level feature_windows, validates
the data is trainable, splits by run_id, fits the LightGBM model
(layer1/model.py), evaluates on each split (evaluation/metrics.py), and
saves the model + metrics under models/layer1/.

Usage:
    python -m detection.layer1.train
    python -m detection.cli train-layer1   # equivalent
"""
from __future__ import annotations

import argparse
import json

from detection.config import MODELS_DIR
from detection.data.extract import load_feature_windows
from detection.data.schema import feature_columns
from detection.data.split import group_stratified_split
from detection.data.validate import print_report
from detection.evaluation.metrics import evaluate_scores, find_best_threshold
from detection.layer1 import model as layer1_model
from detection.layer1.preprocessing import prepare


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--entity-type", default="flow")
    ap.add_argument("--output", default=str(MODELS_DIR / "layer1" / "model.txt"))
    ap.add_argument("--metrics-output", default=str(MODELS_DIR / "layer1" / "metrics.json"))
    args = ap.parse_args()

    df = load_feature_windows(args.entity_type)
    ok = print_report(df, args.entity_type)
    if df.empty:
        raise SystemExit("[layer1] no data to train on")
    if not ok:
        print("[layer1] validation warnings above -- continuing anyway, but check them")

    cols = feature_columns(df)
    print(f"[layer1] {len(cols)} feature columns")

    df_train, df_val, df_test = group_stratified_split(df)
    for name, split in (("train", df_train), ("val", df_val), ("test", df_test)):
        print(f"[layer1] {name}: {len(split)} windows, {split.run_id.nunique()} runs")
    if df_train.empty or df_val.empty:
        raise SystemExit("[layer1] train or val split is empty -- not enough runs")

    booster = layer1_model.fit(
        prepare(df_train, cols), df_train["label"],
        prepare(df_val, cols), df_val["label"],
    )

    val_scores = booster.predict(prepare(df_val, cols), num_iteration=booster.best_iteration)
    threshold = find_best_threshold(df_val["label"].to_numpy(), val_scores, metric="f1")
    print(f"\n[layer1] tuned decision threshold (max F1 on val): {threshold:.3f} "
          f"-- do not assume 0.5, scale_pos_weight shifts this")

    metrics = {}
    for name, split in (("train", df_train), ("val", df_val), ("test", df_test)):
        if split.empty:
            continue
        scores = booster.predict(prepare(split, cols), num_iteration=booster.best_iteration)
        metrics[name] = evaluate_scores(split["label"].to_numpy(), scores, split_name=name, threshold=threshold)

    layer1_model.save(booster, args.output)
    with open(args.metrics_output, "w") as f:
        json.dump({"feature_columns": cols, "threshold": threshold, "metrics": metrics}, f, indent=2)
    print(f"\n[layer1] model saved to {args.output}")
    print(f"[layer1] metrics saved to {args.metrics_output}")

    importances = sorted(
        zip(cols, booster.feature_importance(importance_type="gain")),
        key=lambda kv: kv[1], reverse=True,
    )
    print("\n[layer1] top 15 features by gain:")
    for name, gain in importances[:15]:
        print(f"  {name}: {gain:.1f}")


if __name__ == "__main__":
    main()
