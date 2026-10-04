from __future__ import annotations

import os

import lightgbm as lgb

from detection.config import RANDOM_SEED
from detection.core.base_model import BaseDetectionModel
from detection.core.registry import register_model

DEFAULT_PARAMS = {
    "objective": "binary",
    "metric": ["auc", "average_precision"],
    "boosting_type": "gbdt",
    "num_leaves": 31,
    "learning_rate": 0.05,
    "seed": RANDOM_SEED,
    "verbosity": -1,
}


@register_model("lightgbm")
class LightGBMModel(BaseDetectionModel):
    name = "lightgbm"
    artifact_filename = "model.txt"

    def fit(self, X_train, y_train, X_val, y_val):
        params = {**DEFAULT_PARAMS, **self.params}
        n_pos, n_neg = (y_train == 1).sum(), (y_train == 0).sum()
        params.setdefault("scale_pos_weight", n_neg / max(n_pos, 1))

        train_set = lgb.Dataset(X_train, label=y_train)
        val_set = lgb.Dataset(X_val, label=y_val, reference=train_set)

        self.model = lgb.train(
            params, train_set, num_boost_round=500,
            valid_sets=[train_set, val_set], valid_names=["train", "val"],
            callbacks=[lgb.early_stopping(30), lgb.log_evaluation(50)],
        )
        return self

    def predict_proba(self, X):
        return self.model.predict(X, num_iteration=getattr(self.model, "best_iteration", None))

    def save(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.model.save_model(path)

    @classmethod
    def load(cls, path):
        instance = cls()
        instance.model = lgb.Booster(model_file=path)
        return instance

    def feature_importance(self):
        if self.model is None:
            return None
        return dict(zip(self.model.feature_name(), self.model.feature_importance(importance_type="gain").tolist()))