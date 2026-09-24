"""
Leak-safe train/val/test split: windows from one run never appear in two
splits (they're temporally correlated).

`test` is stratified by (label, scenario), every category with >=2
runs gets at least 1 run in test, because per-family/scenario metrics
and the headline aggregate test score are both read from test, and a
category silently absent from it makes both misleading (see the
module-level discussion in commit history / detection/README.md for
the concrete case that motivated this).

`val` is deliberately NOT stratified by category, it's a plain random
sample of whatever remains after test's per-category allocation. val's
only jobs are early stopping and threshold tuning
(evaluation.metrics.find_best_threshold), neither of which needs every
category represented. Requiring per-category coverage in val as well
starves it down to almost nothing (or a single, possibly single-class,
category) once most categories are too scarce to support a three-way
split, which is common here (several attack families have as few as
2-3 runs total).

Categories with exactly 1 run go straight to train (better to have the
model see it once than lose it entirely) and are surfaced as a warning,
since nothing about their generalization can be measured either way.
"""
from __future__ import annotations

import random
from collections import defaultdict
import pandas as pd
from detection.config import RANDOM_SEED


def _stratify_key(row) -> str:
    return f"{int(row['label'])}:{row['scenario']}"


def group_stratified_split(df: pd.DataFrame, train_frac: float = 0.7, val_frac: float = 0.15,
                           seed: int = RANDOM_SEED, verbose: bool = True):
    rng = random.Random(seed)
    test_frac = max(0.0, 1.0 - train_frac - val_frac)

    run_keys = df.groupby("run_id").apply(lambda g: _stratify_key(g.iloc[0]))
    runs_by_key: dict[str, list] = defaultdict(list)
    for run_id, key in run_keys.items():
        runs_by_key[key].append(run_id)

    train_runs: set = set()
    trainval_pool: list = []
    test_runs: set = set()
    single_run_keys = []

    for key, runs in sorted(runs_by_key.items()):
        runs = runs[:]
        rng.shuffle(runs)
        n = len(runs)

        if n == 1:
            train_runs.update(runs)
            single_run_keys.append(key)
            continue

        n_test = min(max(1, round(n * test_frac)), n - 1)  # >=1 in test, >=1 left for train/val
        test_runs.update(runs[:n_test])
        trainval_pool.extend(runs[n_test:])

    if verbose and single_run_keys:
        print(f"[split] WARNING: {len(single_run_keys)} (label:scenario) categories have "
              f"only 1 run -- placed in train, never appear in test. Test metrics say "
              f"nothing about generalization to these: {single_run_keys}")

    rng.shuffle(trainval_pool)
    denom = train_frac + val_frac
    n_val = round(len(trainval_pool) * (val_frac / denom)) if trainval_pool and denom > 0 else 0
    n_val = min(n_val, max(0, len(trainval_pool) - 1))
    val_runs = set(trainval_pool[:n_val])
    train_runs.update(trainval_pool[n_val:])

    return (
        df[df.run_id.isin(train_runs)].reset_index(drop=True),
        df[df.run_id.isin(val_runs)].reset_index(drop=True),
        df[df.run_id.isin(test_runs)].reset_index(drop=True),
    )


def leave_one_category_out_splits(df: pd.DataFrame):
    """A deliberate, separate evaluation protocol, not the default
    split, for measuring generalization to a completely unseen attack
    family or benign scenario. Trains on every category except one,
    tests only on the held-out one. Yields (held_out_key, train_df,
    test_df) per (label, scenario) category. See
    detection.evaluation.generalization for the runnable version of
    this (it also handles the val-split-within-train needed for
    threshold tuning and early stopping per fold).
    """
    keyed = df.assign(_key=df.apply(_stratify_key, axis=1))
    for key in sorted(keyed["_key"].unique()):
        held_out = keyed[keyed["_key"] == key].drop(columns="_key").reset_index(drop=True)
        rest = keyed[keyed["_key"] != key].drop(columns="_key").reset_index(drop=True)
        yield key, rest, held_out
