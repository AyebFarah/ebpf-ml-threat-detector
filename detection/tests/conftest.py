"""
Shared test helpers. DummyModel needs no ML library, so most tests run in milliseconds
and cannot fail because of lightgbm or xgboost versions.
"""
import json

import numpy as np
import pandas as pd
import pytest

from detection.core.base_model import BaseDetectionModel
from detection.core.registry import register_model


@register_model("_dummy")
class DummyModel(BaseDetectionModel):
    """Scores a row with its first feature, clipped between 0 and 1."""
    name = "_dummy"
    artifact_filename = "dummy.json"

    def fit(self, X_train, y_train, X_val, y_val):
        self.model = {"column": X_train.columns[0]}
        return self

    def predict_proba(self, X):
        return np.clip(X[self.model["column"]].fillna(0).to_numpy(dtype=float), 0.0, 1.0)

    def save(self, path):
        with open(path, "w") as f:
            json.dump(self.model, f)

    @classmethod
    def load(cls, path):
        obj = cls()
        with open(path) as f:
            obj.model = json.load(f)
        return obj

    def feature_importance(self):
        return {self.model["column"]: 1.0}


@pytest.fixture
def models_dir(tmp_path, monkeypatch):
    """Redirects every model file into a temporary folder, so tests never touch models/."""
    from detection import artifacts
    monkeypatch.setattr(artifacts, "MODELS_DIR", tmp_path)
    return tmp_path


@pytest.fixture
def saved_dummy(models_dir):
    """A trained and saved dummy model under host/_dummy/default."""
    from detection import artifacts
    X = pd.DataFrame({"feat_a": [0.1, 0.9], "feat_b": [1.0, 2.0]})
    model = DummyModel().fit(X, [0, 1], X, [0, 1])
    artifacts.save_bundle("host", "_dummy", "default", model, ["feat_a", "feat_b"], 0.5,
                          {}, None, "test.db", {"test_run_ids": [1, 2]})
    return model