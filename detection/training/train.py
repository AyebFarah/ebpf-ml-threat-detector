from __future__ import annotations

import pandas as pd

import detection.algorithms  # noqa: F401
from detection import artifacts
from detection.config import DB_PATH, DEFAULT_MODEL, DEFAULT_VARIANT, RANDOM_SEED
from detection.core.preprocessing import prepare
from detection.core.registry import get_model_class
from detection.data.extract import load_feature_windows
from detection.data.schema import feature_columns
from detection.data.split import group_stratified_split
from detection.data.validate import print_report, validate
from detection.evaluation.metrics import evaluate_scores, find_best_threshold

SUMMARY_KEYS = ("roc_auc", "pr_auc", "precision", "recall", "f1", "false_positive_rate")


def _run_ids(df) -> list[int]:
    return sorted(int(r) for r in df.run_id.unique())


def _print_summary(splits: dict, metrics: dict, threshold: float) -> None:
    rows = [{"split": name, "rows": len(splits[name]), **{k: m[k] for k in SUMMARY_KEYS}}
            for name, m in metrics.items()]
    table = pd.DataFrame(rows).set_index("split")
    print(f"[train] decision threshold {threshold:.3f} (tuned on validation)")
    print(table.round(4).to_string())


def run(entity_type: str = "flow", model_name: str = DEFAULT_MODEL, db_path=DB_PATH,
        variant: str = DEFAULT_VARIANT, params: dict | None = None,
        show_validation: bool = False, show_split: bool = False,
        full_metrics: bool = False) -> dict:
    print(f"[train] {entity_type} / {model_name} / {variant}")

    df = load_feature_windows(db_path, entity_type)
    if df.empty:
        raise SystemExit(f"[train] no data for entity_type='{entity_type}'")

    if show_validation:
        print_report(df, entity_type)
    else:
        warnings = validate(df, entity_type)
        if warnings:
            print(f"[train] {len(warnings)} data warnings hidden (add --validate to show them)")

    cols = feature_columns(df)
    df_train, df_val, df_test = group_stratified_split(df, seed=RANDOM_SEED, verbose=show_split)
    splits = {"train": df_train, "val": df_val, "test": df_test}
    if show_split:
        for name, split in splits.items():
            print(f"[train] {name}: {len(split)} windows, {split.run_id.nunique()} runs")
    if df_train.empty or df_val.empty:
        raise SystemExit("[train] train or val split is empty, not enough runs")

    features = {name: prepare(split, cols) for name, split in splits.items() if not split.empty}

    model = get_model_class(model_name)(params=params)
    model.fit(features["train"], df_train["label"], features["val"], df_val["label"])

    val_scores = model.predict_proba(features["val"])
    threshold = find_best_threshold(df_val["label"].to_numpy(), val_scores, metric="f1")

    metrics = {
        name: evaluate_scores(splits[name]["label"].to_numpy(), model.predict_proba(X),
                              split_name=name, threshold=threshold, verbose=full_metrics)
        for name, X in features.items()
    }
    if not full_metrics:
        _print_summary(splits, metrics, threshold)

    model_path = artifacts.save_bundle(
        entity_type, model_name, variant, model, cols, threshold, metrics, params, db_path,
        split_info={
            "random_state": RANDOM_SEED, "group_column": "run_id",
            "train_run_ids": _run_ids(df_train),
            "val_run_ids": _run_ids(df_val),
            "test_run_ids": _run_ids(df_test),
        },
    )
    print(f"[train] model saved to {model_path}")

    importances = model.feature_importance()
    if importances:
        top_n = 15 if full_metrics else 5
        print(f"[train] top {top_n} features by importance:")
        for name, score in sorted(importances.items(), key=lambda kv: kv[1], reverse=True)[:top_n]:
            print(f"  {name}: {score:.1f}")

    return {"model": model, "threshold": threshold, "feature_columns": cols, "metrics": metrics}