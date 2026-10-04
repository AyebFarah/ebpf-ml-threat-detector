import pytest

from detection import artifacts


def test_reading_paths_never_creates_directories(models_dir):
    artifacts.metrics_path("host", "lightgbm")
    assert list(models_dir.iterdir()) == []


def test_untrained_model_is_not_listed(models_dir):
    artifacts.model_dir("host", "ghost", create=True)
    assert artifacts.list_trained_models("host") == []


def test_save_then_load_round_trip(saved_dummy):
    assert artifacts.list_trained_models("host") == ["_dummy"]
    bundle = artifacts.load_bundle("host", "_dummy")
    assert bundle.threshold == 0.5
    assert bundle.feature_cols == ["feat_a", "feat_b"]
    assert bundle.model.model == saved_dummy.model


def test_loading_a_missing_model_explains_how_to_train_it(models_dir):
    with pytest.raises(FileNotFoundError, match="python -m detection.cli train"):
        artifacts.load_bundle("host", "_dummy")


def test_load_split_returns_the_saved_test_runs(saved_dummy):
    assert artifacts.load_split("host", "_dummy")["test_run_ids"] == [1, 2]


def test_promote_copies_a_variant_so_it_can_be_loaded(saved_dummy):
    artifacts.promote("host", "_dummy", "default", to="best")
    assert artifacts.load_bundle("host", "_dummy", "best").threshold == 0.5