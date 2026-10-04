from __future__ import annotations

import joblib
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from detection.core.base_model import BaseDetectionModel
from detection.core.registry import register_model


@register_model("logistic_regression")
class LogisticRegressionModel(BaseDetectionModel):
    name = "logistic_regression"
    artifact_filename = "model.joblib"

    def fit(self, X_train, y_train, X_val, y_val):
        self.model = Pipeline([
            ("impute", SimpleImputer(strategy="median")),
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", **self.params)),
        ])
        self.model.fit(X_train, y_train)
        return self

    def feature_importance(self):
        if self.model is None:
            return None
        clf = self.model.named_steps["clf"]
        imputer = self.model.named_steps["impute"]
        if not hasattr(imputer, "feature_names_in_"):
            return None
        return dict(zip(imputer.feature_names_in_, abs(clf.coef_[0]).tolist()))

    def predict_proba(self, X):
        return self.model.predict_proba(X)[:, 1]

    def save(self, path):
        joblib.dump(self.model, path)

    @classmethod
    def load(cls, path):
        instance = cls()
        instance.model = joblib.load(path)
        return instance