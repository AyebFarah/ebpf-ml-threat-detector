from __future__ import annotations

import xgboost as xgb

from detection.config import RANDOM_SEED
from detection.core.base_model import BaseDetectionModel
from detection.core.registry import register_model

DEFAULT_PARAMS = {
    "n_estimators": 500,
    "learning_rate": 0.05,
    "max_depth": 6,
    "random_state": RANDOM_SEED,
    "eval_metric": "aucpr",
}


@register_model("xgboost")
class XGBoostModel(BaseDetectionModel):
    name = "xgboost"
    artifact_filename = "model.json"

    def fit(self, X_train, y_train, X_val, y_val):
        params = {**DEFAULT_PARAMS, **self.params}
        n_pos, n_neg = (y_train == 1).sum(), (y_train == 0).sum()
        params.setdefault("scale_pos_weight", n_neg / max(n_pos, 1))

        self.model = xgb.XGBClassifier(**params, early_stopping_rounds=30)
        self.model.fit(
            X_train.fillna(-999), y_train,
            eval_set=[(X_val.fillna(-999), y_val)], verbose=50,
        )
        return self

    def predict_proba(self, X):
        return self.model.predict_proba(X.fillna(-999))[:, 1]

    def save(self, path):
        self.model.save_model(path)

    @classmethod
    def load(cls, path):
        instance = cls()
        instance.model = xgb.XGBClassifier()
        instance.model.load_model(path)
        return instance

    def feature_importance(self):
        if self.model is None:
            return None
        return self.model.get_booster().get_score(importance_type="gain")