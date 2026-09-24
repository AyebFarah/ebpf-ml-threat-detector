"""
Leave-one-category-out (LOFO) generalization evaluation: trains Layer 1
on every (label, scenario) category except one, tests only on the
held-out category, and repeats per category. Answers "how well does the
model do on an attack family (or benign scenario) it has never seen"

Note on metrics: a held-out category is homogeneous in label by
construction (every 'port_scan' row has label=1), so ROC-AUC/PR-AUC are
undefined on it, there's no negative class to rank against within the
held-out set itself. What's actually reported per category is:
  - attack category (label=1): detection_rate: fraction of its
    windows the model still flagged as attack, despite never training
    on this family.
  - benign category (label=0): false_positive_rate: fraction of its
    windows the model wrongly flagged as attack.

This is deliberately Layer-1-specific for now.

Usage:
    python -m detection.evaluation.generalization
    python -m detection.cli evaluate-generalization
"""
from __future__ import annotations

import argparse
import json
import os
import random

from detection.config import EXPERIMENTS_DIR, RANDOM_SEED
from detection.data.extract import load_feature_windows
from detection.data.schema import feature_columns
from detection.data.split import leave_one_category_out_splits
from detection.evaluation.metrics import find_best_threshold
from detection.layer1 import model as layer1_model
from detection.layer1.preprocessing import prepare


def run(entity_type: str = "flow", min_held_out_runs: int = 1) -> dict:
    df = load_feature_windows(entity_type)
    cols = feature_columns(df)
    rng = random.Random(RANDOM_SEED)

    results = {}
    for key, train_df, held_out_df in leave_one_category_out_splits(df):
        label_str, scenario = key.split(":", 1)
        label = int(label_str)
        n_runs = held_out_df["run_id"].nunique()
        if n_runs < min_held_out_runs:
            continue

        train_runs = list(train_df["run_id"].unique())
        if len(train_runs) < 4:
            print(f"[generalization] skipping '{key}': only {len(train_runs)} runs "
                  f"remain after holding it out -- not enough to train+validate on")
            continue

        n_val_runs = max(1, len(train_runs) // 10)
        val_run_ids = set(rng.sample(train_runs, n_val_runs))
        val_df = train_df[train_df.run_id.isin(val_run_ids)]
        fit_df = train_df[~train_df.run_id.isin(val_run_ids)]

        if fit_df["label"].nunique() < 2 or val_df["label"].nunique() < 2:
            print(f"[generalization] skipping '{key}': holding it out left train or val "
                  f"with only one class -- can't fit a binary classifier on what's left")
            continue

        booster = layer1_model.fit(
            prepare(fit_df, cols), fit_df["label"],
            prepare(val_df, cols), val_df["label"],
        )

        # Fresh model each fold -> fresh threshold each fold. Tuned on
        # this fold's own val split, never on the held-out category
        # itself (see find_best_threshold's docstring for why).
        val_scores = booster.predict(prepare(val_df, cols), num_iteration=booster.best_iteration)
        threshold = find_best_threshold(val_df["label"].to_numpy(), val_scores, metric="f1")

        scores = booster.predict(prepare(held_out_df, cols), num_iteration=booster.best_iteration)
        preds = (scores >= threshold).astype(int)

        metric_name = "detection_rate" if label == 1 else "false_positive_rate"
        metric_value = float(preds.mean())

        print(f"\n=== held out: {key} ({n_runs} runs, {len(held_out_df)} windows) ===")
        print(f"{metric_name}: {metric_value:.3f}  (threshold={threshold:.3f}, "
              f"mean predicted score: {scores.mean():.3f})")

        results[key] = {
            "label": label,
            "scenario": scenario,
            "n_held_out_runs": int(n_runs),
            "n_held_out_windows": int(len(held_out_df)),
            "threshold": threshold,
            metric_name: metric_value,
            "mean_score": float(scores.mean()),
        }

    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--entity-type", default="flow")
    ap.add_argument("--min-held-out-runs", type=int, default=1)
    ap.add_argument("--output", default=str(EXPERIMENTS_DIR / "reports" / "generalization.json"))
    args = ap.parse_args()

    results = run(args.entity_type, args.min_held_out_runs)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[generalization] wrote {args.output}")

    print("\n=== summary ===")
    for key, m in sorted(results.items()):
        metric = "detection_rate" if m["label"] == 1 else "false_positive_rate"
        print(f"  {key}: {metric}={m[metric]:.3f}  ({m['n_held_out_runs']} runs held out)")


if __name__ == "__main__":
    main()
