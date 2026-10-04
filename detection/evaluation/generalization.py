from __future__ import annotations

import json
import random

import detection.algorithms  # noqa: F401
from detection.config import DB_PATH, DEFAULT_MODEL, RANDOM_SEED, REPORTS_DIR
from detection.core.preprocessing import prepare
from detection.core.registry import get_model_class
from detection.data.extract import load_feature_windows
from detection.data.schema import feature_columns
from detection.data.split import leave_one_category_out_splits
from detection.evaluation.metrics import find_best_threshold


def _pick_val_runs(train_df, rng) -> set:
    """Picks validation runs from EACH class, so threshold tuning always sees both."""
    run_labels = train_df.groupby("run_id")["label"].first()
    chosen: set = set()
    for label in (0, 1):
        ids = run_labels[run_labels == label].index.tolist()
        if len(ids) >= 2:  # keep at least one run of this class for fitting
            chosen.update(rng.sample(ids, max(1, len(ids) // 5)))
    return chosen


def run(entity_type: str = "flow", db_path=DB_PATH, model_name: str = DEFAULT_MODEL,
        min_held_out_runs: int = 1) -> dict:
    df = load_feature_windows(db_path, entity_type)
    cols = feature_columns(df)
    rng = random.Random(RANDOM_SEED)
    ModelClass = get_model_class(model_name)

    results = {}
    for key, train_df, held_out_df in leave_one_category_out_splits(df):
        label = int(key.split(":", 1)[0])
        scenario = key.split(":", 1)[1]
        n_runs = held_out_df["run_id"].nunique()
        if n_runs < min_held_out_runs:
            continue

        val_ids = _pick_val_runs(train_df, rng)
        val_df = train_df[train_df.run_id.isin(val_ids)]
        fit_df = train_df[~train_df.run_id.isin(val_ids)]
        if fit_df["label"].nunique() < 2 or val_df["label"].nunique() < 2:
            print(f"[generalization] skipping '{key}': not enough runs left to fit and validate")
            continue

        model = ModelClass()
        model.fit(prepare(fit_df, cols), fit_df["label"], prepare(val_df, cols), val_df["label"])
        threshold = find_best_threshold(val_df["label"].to_numpy(),
                                        model.predict_proba(prepare(val_df, cols)), metric="f1")

        scores = model.predict_proba(prepare(held_out_df, cols))
        rate = float((scores >= threshold).mean())
        metric_name = "detection_rate" if label == 1 else "false_positive_rate"

        print(f"\n=== held out: {key} ({n_runs} runs, {len(held_out_df)} windows) ===")
        print(f"{metric_name}: {rate:.3f}  (threshold={threshold:.3f}, mean score {scores.mean():.3f})")
        results[key] = {"label": label, "scenario": scenario, "n_held_out_runs": int(n_runs),
                        "n_held_out_windows": int(len(held_out_df)), "threshold": threshold,
                        metric_name: rate, "mean_score": float(scores.mean())}

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORTS_DIR / f"generalization_{entity_type}_{model_name}.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"\n[generalization] wrote {out}")
    return results