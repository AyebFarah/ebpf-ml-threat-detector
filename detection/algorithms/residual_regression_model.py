"""
Residual, error based anomaly detection using gradient boosting
regressors. One regressor is trained per feature, predicting that
feature's value from every OTHER feature, deliberately excluding the
feature from its own input set, otherwise the regressor would learn
the trivial, useless solution of copying the value back to itself with
zero error.

Training uses only benign rows, the same "learn what normal looks
like" principle as the Isolation Forest and HDBSCAN models, expressed
through regression instead of density or isolation. For a row
resembling normal traffic, the learned relationships between features
hold, and every feature's reconstruction stays close to its true
value, low residual. For an anomalous row, those relationships break
down, and the residual, the reconstruction error, rises. The anomaly
score is the mean squared residual across every feature, rescaled into
the same 0 to 1 range every other Layer 1 model returns.

Training one regressor per feature is more expensive than a single
model, for a dataset with n features this trains n regressors. A
max_features parameter is exposed to restrict this to a subset (for
example, the highest variance features) if the full feature count
makes training too slow to iterate on comfortably.
"""
from __future__ import annotations

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.preprocessing import MinMaxScaler

from detection.core.base_model import BaseDetectionModel
from detection.core.registry import register_model


@register_model("residual_regression")
class ResidualRegressionModel(BaseDetectionModel):
    name = "residual_regression"
    artifact_filename = "model.joblib"

    def fit(self, X_train, y_train, X_val, y_val):
        self._median_fill = X_train.median()
        X_train_filled = X_train.fillna(self._median_fill)
        X_benign = X_train_filled.loc[y_train == 0]

        max_features = self.params.get("max_features")
        columns = list(X_train.columns)
        if max_features and len(columns) > max_features:
            columns = X_benign.var().sort_values(ascending=False).head(max_features).index.tolist()
        self._columns = columns

        self._regressors = {}
        for target_col in self._columns:
            input_cols = [c for c in self._columns if c != target_col]
            regressor = GradientBoostingRegressor(
                n_estimators=self.params.get("n_estimators", 100),
                max_depth=self.params.get("max_depth", 3),
                random_state=self.params.get("random_state", 42),
            )
            regressor.fit(X_benign[input_cols], X_benign[target_col])
            self._regressors[target_col] = regressor

        raw_train_residuals = self._residuals(X_train_filled)
        self._scaler = MinMaxScaler(clip=True)
        self._scaler.fit(raw_train_residuals.reshape(-1, 1))
        return self

    def _residuals(self, X_filled):
        squared_error_sum = np.zeros(len(X_filled))
        for target_col, regressor in self._regressors.items():
            input_cols = [c for c in self._columns if c != target_col]
            predicted = regressor.predict(X_filled[input_cols])
            actual = X_filled[target_col].to_numpy()
            squared_error_sum += (actual - predicted) ** 2
        return squared_error_sum / len(self._columns)

    def predict_proba(self, X):
        residuals = self._residuals(X.fillna(self._median_fill))
        return self._scaler.transform(residuals.reshape(-1, 1)).ravel()

    def save(self, path):
        joblib.dump({
            "regressors": self._regressors, "columns": self._columns,
            "scaler": self._scaler, "median_fill": self._median_fill,
        }, path)

    @classmethod
    def load(cls, path):
        payload = joblib.load(path)
        instance = cls()
        instance._regressors = payload["regressors"]
        instance._columns = payload["columns"]
        instance._scaler = payload["scaler"]
        instance._median_fill = payload["median_fill"]
        return instance