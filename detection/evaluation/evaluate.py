from __future__ import annotations

import pandas as pd
from datetime import datetime, timezone

from detection import artifacts
from detection.config import DB_PATH, DEFAULT_VARIANT
from detection.core.preprocessing import prepare
from detection.data.extract import load_feature_windows
from detection.evaluation.metrics import evaluate_scores, flag_rate_by_group


def evaluate_one(entity_type: str, model_name: str, variant: str, df: pd.DataFrame) -> dict:
    bundle = artifacts.load_bundle(entity_type, model_name, variant)
    test_ids = set(artifacts.load_split(entity_type, model_name, variant)["test_run_ids"])
    df_test = df[df.run_id.isin(test_ids)].reset_index(drop=True)
    if df_test.empty:
        print(f"[evaluate] {model_name}/{variant}: empty test split, skipping")
        return {}

    scores = bundle.model.predict_proba(prepare(df_test, bundle.feature_cols))
    print(f"\n== {model_name}/{variant} (threshold={bundle.threshold:.3f}) ==")
    result = evaluate_scores(df_test["label"].to_numpy(), scores,
                             split_name="test", threshold=bundle.threshold)

    result["detection_rate_by_family"] = flag_rate_by_group(
        df_test, scores, bundle.threshold, 1, "attack_family")
    result["false_positive_rate_by_scenario"] = flag_rate_by_group(
        df_test, scores, bundle.threshold, 0, "scenario")

    print("\ndetection rate per attack family:")
    for family, rate in result["detection_rate_by_family"].items():
        print(f"  {family:<20} {rate:.3f}")
    print("false positive rate per benign scenario:")
    for scenario, rate in result["false_positive_rate_by_scenario"].items():
        print(f"  {scenario:<20} {rate:.3f}")

    payload = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "threshold": bundle.threshold,
        "test_rows": len(df_test),
        "test_runs": int(df_test.run_id.nunique()),
        **result,
    }
    saved = artifacts.save_evaluation(entity_type, model_name, variant, payload)
    print(f"[evaluate] saved {saved}")
    return payload


def run(entity_type: str = "flow", db_path=DB_PATH, models: list[str] | None = None,
        variant: str = DEFAULT_VARIANT) -> dict:
    df = load_feature_windows(db_path, entity_type)
    names = models or artifacts.list_trained_models(entity_type, variant)
    if not names:
        raise SystemExit(f"[evaluate] no trained models for entity_type='{entity_type}' variant='{variant}'")
    return {name: evaluate_one(entity_type, name, variant, df) for name in names}