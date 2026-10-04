"""
Hybrid semi supervised anomaly detection, following the XGBOD approach
(Zhao and Hryniewicki, 2018). A small panel of unsupervised outlier
detectors, Isolation Forest and Local Outlier Factor, are fit first,
entirely without using labels, each producing one additional "outlier
score" column per row. Those columns are concatenated onto the
original feature columns, and a gradient boosted classifier is trained
on the combined feature set using the true attack or benign labels.

This lets the final classifier draw on both paradigms: whatever
structure the unsupervised detectors found entirely on their own, plus
the ground truth labels this project's attack lab already provides,
rather than being forced to pick one paradigm over the other.
"""
from __future__ import annotations

import joblib
import numpy as np
import xgboost as xgb
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

from detection.config import RANDOM_SEED
from detection.core.base_model import BaseDetectionModel
from detection.core.registry import register_model
from detection.algorithms.xgboost_model import DEFAULT_PARAMS as XGB_DEFAULT_PARAMS


class _UnsupervisedScorers:
    """Fits a small panel of unsupervised outlier detectors once, on
    the training data only, labels unused entirely, and reuses them to
    score any later data, train, validation, or test, consistently."""

    def __init__(self, random_state=RANDOM_SEED):
        self.isolation_forest = IsolationForest(n_estimators=200, random_state=random_state)
        # novelty=True is required so LOF can score points outside its
        # own training set; its default mode can only score the exact
        # rows it was fit on, unusable for a held out split.
        self.lof = LocalOutlierFactor(n_neighbors=20, novelty=True)

    def fit(self, X_filled):
        arr = X_filled.to_numpy() if hasattr(X_filled, "to_numpy") else X_filled
        self.isolation_forest.fit(arr)
        self.lof.fit(arr)
        return self

    def transform(self, X_filled):
        arr = X_filled.to_numpy() if hasattr(X_filled, "to_numpy") else X_filled
        iforest_score = -self.isolation_forest.decision_function(arr)
        lof_score = -self.lof.decision_function(arr)
        return np.column_stack([iforest_score, lof_score])


@register_model("xgbod")
class XGBODModel(BaseDetectionModel):
    name = "xgbod"
    artifact_filename = "model.json"

    def fit(self, X_train, y_train, X_val, y_val):
        self._columns = list(X_train.columns)
        self._median_fill = X_train.median()
        X_train_filled = X_train.fillna(self._median_fill)
        X_val_filled = X_val.fillna(self._median_fill)

        self._scorers = _UnsupervisedScorers().fit(X_train_filled)
        X_train_augmented = np.column_stack([X_train_filled.to_numpy(), self._scorers.transform(X_train_filled)])
        X_val_augmented = np.column_stack([X_val_filled.to_numpy(), self._scorers.transform(X_val_filled)])

        params = {**XGB_DEFAULT_PARAMS, **self.params}
        n_pos, n_neg = (y_train == 1).sum(), (y_train == 0).sum()
        params.setdefault("scale_pos_weight", n_neg / max(n_pos, 1))

        self.model = xgb.XGBClassifier(**params, early_stopping_rounds=30)
        self.model.fit(X_train_augmented, y_train, eval_set=[(X_val_augmented, y_val)], verbose=50)
        return self

    def _augment(self, X):
        X_filled = X.fillna(self._median_fill)
        return np.column_stack([X_filled.to_numpy(), self._scorers.transform(X_filled)])

    def predict_proba(self, X):
        return self.model.predict_proba(self._augment(X))[:, 1]

    def save(self, path):
        self.model.save_model(path)
        joblib.dump(
            {"scorers": self._scorers, "median_fill": self._median_fill, "columns": self._columns},
            path.replace(".json", "_aux.joblib"),
        )

    @classmethod
    def load(cls, path):
        instance = cls()
        instance.model = xgb.XGBClassifier()
        instance.model.load_model(path)
        aux = joblib.load(path.replace(".json", "_aux.joblib"))
        instance._scorers = aux["scorers"]
        instance._median_fill = aux["median_fill"]
        instance._columns = aux["columns"]
        return instance

    def feature_importance(self):
        if self.model is None:
            return None
        names = self._columns + ["outlier_score_isolation_forest", "outlier_score_lof"]
        return dict(zip(names, self.model.feature_importances_.tolist()))