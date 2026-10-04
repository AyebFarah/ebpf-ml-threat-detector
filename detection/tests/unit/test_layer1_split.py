"""
The single most important test in detection/. If group_stratified_split
ever let one run_id's rows appear in two different splits, every metric
downstream (ROC AUC, recall, everything in the report) becomes invalid
silently, no exception is raised, the number is just wrong.
"""
import pandas as pd
import warnings

from detection.data.split import group_stratified_split


def _fake_feature_windows(n_runs: int = 20, rows_per_run: int = 10) -> pd.DataFrame:
    rows = []
    for run_id in range(n_runs):
        label = run_id % 2  # alternate benign/attack runs
        scenario = "ssh_bruteforce" if label else "idle_desktop"
        for i in range(rows_per_run):
            rows.append({"run_id": run_id, "label": label, "scenario": scenario, "window_start_ts": i})
    return pd.DataFrame(rows)


def test_no_run_id_appears_in_two_splits():
    df = _fake_feature_windows()
    df_train, df_val, df_test = group_stratified_split(df, seed=42)

    train_runs = set(df_train.run_id.unique())
    val_runs = set(df_val.run_id.unique())
    test_runs = set(df_test.run_id.unique())

    assert train_runs.isdisjoint(val_runs), "a run_id appears in both train and val"
    assert train_runs.isdisjoint(test_runs), "a run_id appears in both train and test"
    assert val_runs.isdisjoint(test_runs), "a run_id appears in both val and test"


def test_every_row_lands_in_exactly_one_split():
    df = _fake_feature_windows()
    df_train, df_val, df_test = group_stratified_split(df, seed=42)
    assert len(df_train) + len(df_val) + len(df_test) == len(df)


def test_every_category_with_at_least_two_runs_appears_in_test():
    df = _fake_feature_windows(n_runs=20)
    _, _, df_test = group_stratified_split(df, seed=42)
    test_categories = set((r.label, r.scenario) for r in df_test.itertuples())
    assert (1, "ssh_bruteforce") in test_categories
    assert (0, "idle_desktop") in test_categories


def test_single_run_category_goes_to_train_not_lost():
    df = _fake_feature_windows(n_runs=20)
    rare_row = {"run_id": 999, "label": 1, "scenario": "rare_attack", "window_start_ts": 0}
    df = pd.concat([df, pd.DataFrame([rare_row])], ignore_index=True)

    df_train, df_val, df_test = group_stratified_split(df, seed=42)
    all_run_ids = set(df_train.run_id) | set(df_val.run_id) | set(df_test.run_id)
    assert 999 in all_run_ids, "a single-run category must not be silently dropped"
    assert 999 not in set(df_val.run_id), "a single-run category has nothing to validate against, should not land in val"

def test_split_is_deterministic_for_the_same_seed():
    df = _fake_feature_windows()
    first = group_stratified_split(df, seed=7, verbose=False)
    second = group_stratified_split(df, seed=7, verbose=False)
    for a, b in zip(first, second):
        assert sorted(a.run_id.unique()) == sorted(b.run_id.unique())

def test_split_raises_no_pandas_warnings():
    df = _fake_feature_windows()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        group_stratified_split(df, seed=42, verbose=False)

def test_near_miss_scenarios_reach_the_test_split():
    df = _fake_feature_windows(n_runs=20)
    extra = pd.DataFrame([{"run_id": 100 + i, "label": 0, "scenario": "ssh_retry_storm",
                           "window_start_ts": 0} for i in range(3)])
    _, _, df_test = group_stratified_split(pd.concat([df, extra], ignore_index=True),
                                           seed=42, verbose=False)
    assert "ssh_retry_storm" in set(df_test.scenario)