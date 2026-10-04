"""
Isolation Forest, a bagging family algorithm, used here as a semi
supervised novelty detector rather than a fully unsupervised one: it
is fit only on rows labeled benign in the training split, learning
what "normal" looks like, then scores every row, benign or attack,
train or test, by how easily it can be isolated from that learned
notion of normal.

Isolation Forest already handles multiple features jointly by
construction, every split it makes picks a random feature and a
random threshold, and a row's isolation depth reflects its position
across the whole feature space at once, not one feature at a time.
This is what "multivariate" means for this algorithm, no separate
implementation is needed for a single feature versus many features.

Isolation Forest's own decision_function returns HIGHER values for
NORMAL points and lower for anomalies, the opposite convention from
predict_proba, so the raw score is negated, then rescaled with a
MinMaxScaler fit on the training data into the same 0 to 1 range every
other Layer 1 model already returns, so it needs no special casing
anywhere downstream.
"""
from __future__ import annotations

import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler

from detection.core.base_model import BaseDetectionModel
from detection.core.registry import register_model


@register_model("isolation_forest")
class IsolationForestModel(BaseDetectionModel):
    name = "isolation_forest"
    artifact_filename = "model.joblib"

    def fit(self, X_train, y_train, X_val, y_val):
        self._median_fill = X_train.median()
        X_train_filled = X_train.fillna(self._median_fill)
        X_benign = X_train_filled.loc[y_train == 0]

        self.model = IsolationForest(
            n_estimators=self.params.get("n_estimators", 200),
            contamination=self.params.get("contamination", "auto"),
            random_state=self.params.get("random_state", 42),
        )
        self.model.fit(X_benign)

        raw_train_scores = -self.model.decision_function(X_train_filled)
        self._scaler = MinMaxScaler(clip=True)
        self._scaler.fit(raw_train_scores.reshape(-1, 1))
        return self

    def predict_proba(self, X):
        X_filled = X.fillna(self._median_fill)
        raw_scores = -self.model.decision_function(X_filled)
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