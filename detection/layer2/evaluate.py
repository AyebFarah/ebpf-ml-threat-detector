from __future__ import annotations

from datetime import datetime, timezone

import numpy as np
import pandas as pd

from detection import artifacts
from detection.config import DB_PATH, DEFAULT_MODEL, DEFAULT_VARIANT, REPORTS_DIR
from detection.data.extract import load_feature_windows
from detection.core.preprocessing import prepare
from detection.evaluation.metrics import evaluate_scores, flag_rate_by_group
from detection.layer2.dataset import load_graphs
from detection.layer2.schema import (BASELINE_MODEL, BASELINE_VARIANT, GRAPH_ENTITY, resolve_model)
from detection.layer2.predict import score_windows

SUMMARY_KEYS = ("roc_auc", "pr_auc", "precision", "recall", "f1", "false_positive_rate")


def _test_positions(ds, bundle_model: str, variant: str):
    test_ids = set(artifacts.load_split(GRAPH_ENTITY, bundle_model, variant)["test_run_ids"])
    return np.flatnonzero(ds.index["run_id"].isin(test_ids).to_numpy()), test_ids


def run(model_name: str = "graphsage", variant: str = DEFAULT_VARIANT, baseline: bool = False) -> dict:
    model_name, variant = resolve_model(model_name, variant, baseline)
    ds = load_graphs()
    bundle = artifacts.load_bundle(GRAPH_ENTITY, model_name, variant)
    positions, _ = _test_positions(ds, model_name, variant)
    test = ds.index.iloc[positions].reset_index(drop=True)
    if test.empty:
        raise SystemExit("[layer2 evaluate] empty test split")

    scores = score_windows(bundle, ds, positions)
    print(f"\n== {model_name}/{variant} (threshold={bundle.threshold:.3f}) ==")
    result = evaluate_scores(test["label"].to_numpy(), scores, split_name="test",
                             threshold=bundle.threshold)
    result["detection_rate_by_family"] = flag_rate_by_group(test, scores, bundle.threshold, 1, "attack_family")
    result["false_positive_rate_by_scenario"] = flag_rate_by_group(test, scores, bundle.threshold, 0, "scenario")

    print("\ndetection rate per attack family:")
    for family, rate in result["detection_rate_by_family"].items():
        print(f"  {family:<22} {rate:.3f}")
    print("false positive rate per benign scenario:")
    for scenario, rate in result["false_positive_rate_by_scenario"].items():
        print(f"  {scenario:<22} {rate:.3f}")

    payload = {"evaluated_at": datetime.now(timezone.utc).isoformat(), "threshold": bundle.threshold,
               "test_rows": len(test), "test_runs": int(test.run_id.nunique()), **result}
    print(f"[layer2 evaluate] saved {artifacts.save_evaluation(GRAPH_ENTITY, model_name, variant, payload)}")
    return payload


def compare(db_path=DB_PATH, gnn_model="graphsage", layer1_model=DEFAULT_MODEL, seq_models=()) -> None:
    """Layer 1 vs graph statistics baseline vs GNN, on the identical test windows."""
    ds = load_graphs()
    gnn = artifacts.load_bundle(GRAPH_ENTITY, gnn_model, DEFAULT_VARIANT)
    base = artifacts.load_bundle(GRAPH_ENTITY, BASELINE_MODEL, BASELINE_VARIANT)
    layer1 = artifacts.load_bundle("host", layer1_model, DEFAULT_VARIANT)

    positions, test_ids = _test_positions(ds, gnn_model, DEFAULT_VARIANT)
    layer1_ids = set(artifacts.load_split("host", layer1_model, DEFAULT_VARIANT)["test_run_ids"])
    if test_ids != layer1_ids:
        print("[compare] WARNING: Layer 1 and Layer 2 test runs differ, the comparison is NOT fair. "
              "Retrain both from the same database.")

    test = ds.index.iloc[positions].reset_index(drop=True)
    host = load_feature_windows(db_path, "host").set_index("id").loc[test["window_id"]].reset_index()

    scored = {
        f"layer1_{layer1_model}": (layer1.model.predict_proba(prepare(host, layer1.feature_cols)), layer1.threshold),
        "graph_stats_baseline": (score_windows(base, ds, positions), base.threshold),
        f"layer2_{gnn_model}": (score_windows(gnn, ds, positions), gnn.threshold),
    }
    for name in seq_models:
        seq = artifacts.load_bundle(GRAPH_ENTITY, name, DEFAULT_VARIANT)
        scored[f"layer2_{name}"] = (score_windows(seq, ds, positions), seq.threshold)

    y = test["label"].to_numpy()
    overall, detection, false_alarms = {}, {}, {}
    for name, (scores, thr) in scored.items():
        m = evaluate_scores(y, scores, threshold=thr, verbose=False)
        overall[name] = {k: m[k] for k in SUMMARY_KEYS}
        detection[name] = flag_rate_by_group(test, scores, thr, 1, "attack_family")
        false_alarms[name] = flag_rate_by_group(test, scores, thr, 0, "scenario")

    tables = {"metrics": pd.DataFrame(overall).T, "detection_by_family": pd.DataFrame(detection),
              "false_positive_by_scenario": pd.DataFrame(false_alarms)}
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"\n[compare] {len(test)} test windows from {test.run_id.nunique()} runs")
    for title, table in tables.items():
        print(f"\n{title}")
        print(table.round(3).to_string())
        table.round(4).to_csv(REPORTS_DIR / f"layer2_compare_{title}.csv")
    print(f"\n[compare] CSV files written to {REPORTS_DIR}")