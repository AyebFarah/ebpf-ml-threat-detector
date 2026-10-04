"""
HDBSCAN, a density based clustering algorithm from the same family as
DBSCAN, used in the same semi supervised novelty setup as the
Isolation Forest model: clusters of "normal" behavior are learned only
from benign training rows, and a row far from every learned cluster is
scored as anomalous.

Plain DBSCAN has no mechanism to score a point outside its original
training set, it only labels the points it clustered during fitting.
HDBSCAN's approximate_predict solves exactly this gap, which is the
reason HDBSCAN, rather than plain DBSCAN, is used here, it is the
direct, prediction capable variant of the same density based family.
"""
from __future__ import annotations

import hdbscan
import joblib
import numpy as np
from sklearn.preprocessing import MinMaxScaler

from detection.core.base_model import BaseDetectionModel
from detection.core.registry import register_model


@register_model("hdbscan")
class HDBSCANModel(BaseDetectionModel):
    name = "hdbscan"
    artifact_filename = "model.joblib"

    def fit(self, X_train, y_train, X_val, y_val):
        self._median_fill = X_train.median()
        X_train_filled = X_train.fillna(self._median_fill)
        X_benign = X_train_filled.loc[y_train == 0]

        self.model = hdbscan.HDBSCAN(
            min_cluster_size=self.params.get("min_cluster_size", 15),
            prediction_data=True,  # required by approximate_predict later
        )
        self.model.fit(X_benign.to_numpy())

        raw_train_scores = self._outlier_scores(X_train_filled)
        self._scaler = MinMaxScaler(clip=True)
        self._scaler.fit(raw_train_scores.reshape(-1, 1))
        return self

    def _outlier_scores(self, X_filled):
        # strength is how confidently a point belongs to its nearest
        # learned "normal" cluster, weak or no membership means the
        # point looks unlike anything seen as normal, so 1 - strength
        # is the anomaly score.
        _, strengths = hdbscan.approximate_predict(self.model, X_filled.to_numpy())
        return 1.0 - strengths

    def predict_proba(self, X):
        raw_scores = self._outlier_scores(X.fillna(self._median_fill))
        return self._scaler.transform(raw_scores.reshape(-1, 1)).ravel()

    def save(self, path):
        joblib.dump({"model": self.model, "scaler": self._scaler, "median_fill": self._median_fill}, path)

    @classmethod
    def load(cls, path):
        payload = joblib.load(path)
        instance = cls()
        instance.model = payload["model"]
        instance._scaler = payload["scaler"]
        instance._median_fill = payload["median_fill"]
        return instance