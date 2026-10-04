"""
ML-readiness checks on a loaded feature_windows DataFrame, run before
training (or standalone via `python -m detection.cli validate`). This is
distinct from the database merge's integrity checks -- those confirm the
DB wasn't corrupted by merging; this confirms the data is actually
usable for training (enough runs per class, no all-null column, etc).
"""
from __future__ import annotations

import pandas as pd

from detection.config import DB_PATH, ENTITY_TYPES
from detection.data.extract import load_feature_windows
from detection.data.schema import feature_columns


def validate(df: pd.DataFrame, entity_type: str) -> list[str]:
    """Returns a list of warning strings; empty list means all checks passed."""
    warnings: list[str] = []

    if df.empty:
        return [f"no rows for entity_type='{entity_type}' -- run windowing first"]

    n_pos = (df["label"] == 1).sum()
    n_neg = (df["label"] == 0).sum()
    if n_pos == 0 or n_neg == 0:
        warnings.append(f"only one class present ({n_pos} attack, {n_neg} benign) -- "
                        f"can't train or meaningfully evaluate a classifier")

    n_runs = df["run_id"].nunique()
    if n_runs < 6:
        warnings.append(f"only {n_runs} distinct runs -- group_stratified_split needs "
                        f"enough runs per class to produce non-empty val/test splits")

    cols = feature_columns(df)
    all_null = [c for c in cols if df[c].isna().all()]
    if all_null:
        warnings.append(f"{len(all_null)} feature columns are 100% null: {all_null}")

    constant = [c for c in cols if df[c].nunique(dropna=True) <= 1]
    if constant:
        warnings.append(f"{len(constant)} feature columns have zero variance: {constant}")

    dup_ids = df["id"].duplicated().sum() if "id" in df.columns else 0
    if dup_ids:
        warnings.append(f"{dup_ids} duplicate feature_windows.id values -- check the merge")

    if "scenario" in df.columns:
        run_scenarios = df.groupby("run_id").agg(label=("label", "first"), scenario=("scenario", "first"))
        category = run_scenarios["label"].astype(int).astype(str) + ":" + run_scenarios["scenario"]
        counts = category.value_counts()
        single_run = counts[counts == 1]
        if not single_run.empty:
            warnings.append(
                f"{len(single_run)} (label:scenario) categories have exactly 1 run -- "
                f"group_stratified_split can only put these in train, so test metrics say "
                f"nothing about generalization to them: {sorted(single_run.index.tolist())}"
            )
        scarce = counts[(counts >= 2) & (counts < 4)]
        if not scarce.empty:
            warnings.append(
                f"{len(scarce)} categories have only 2-3 runs -- they'll appear in train+test "
                f"but likely not val: {sorted(scarce.index.tolist())}. Consider "
                f"detection.evaluation.generalization for a dedicated held-out-category "
                f"evaluation on these rather than trusting the aggregate test metric alone."
            )

    return warnings


def print_report(df: pd.DataFrame, entity_type: str) -> bool:
    """Prints the validation report; returns True if there were no warnings."""
    warnings = validate(df, entity_type)
    print(f"[validate] entity_type='{entity_type}': {len(df)} rows, "
          f"{df['run_id'].nunique() if not df.empty else 0} runs")
    if not warnings:
        print("[validate] no issues found")
        return True
    for w in warnings:
        print(f"[validate] WARNING: {w}")
    return False


def compare_entity_types(db_path: str = DB_PATH, entity_types=None) -> None:
    """Runs validate() for each entity_type and flags columns that are
    dead (zero-variance) in one granularity but carry real signal in
    another -- the signature of a feature that only means something once
    aggregated across multiple flows (destination diversity, JA4
    diversity, SSH session stats)."""
    entity_types = entity_types or ENTITY_TYPES
    dead_by_type = {}

    for et in entity_types:
        df = load_feature_windows(db_path, et)
        if df.empty:
            print(f"[validate] entity_type='{et}': no rows, skipping")
            continue
        cols = feature_columns(df)
        dead_by_type[et] = {c for c in cols if df[c].nunique(dropna=True) <= 1}
        print_report(df, et)
        print()

    types = list(dead_by_type)
    for i, a in enumerate(types):
        for b in types[i + 1:]:
            only_a = dead_by_type[a] - dead_by_type[b]
            if only_a:
                print(f"[validate] {len(only_a)} columns dead in '{a}' but live in '{b}' "
                      f"-- need multi-{a} aggregation to mean anything: {sorted(only_a)}")
            only_b = dead_by_type[b] - dead_by_type[a]
            if only_b:
                print(f"[validate] {len(only_b)} columns dead in '{b}' but live in '{a}': "
                      f"{sorted(only_b)}")