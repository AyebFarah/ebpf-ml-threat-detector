"""
LightGBM model definition for Layer 1: hyperparameters and the
fit/save/load wrappers. Kept separate from train.py so the training loop
(data splits, evaluation, logging) doesn't need to change if the model
itself changes.
"""
from __future__ import annotations

import os

import lightgbm as lgb

from detection.config import RANDOM_SEED

DEFAULT_PARAMS = {
    "objective": "binary",
    "metric": ["auc", "average_precision"],
    "boosting_type": "gbdt",
    "num_leaves": 31,
    "learning_rate": 0.05,
    "seed": RANDOM_SEED,
    "verbosity": -1,
}


def compute_scale_pos_weight(y) -> float:
    n_pos = (y == 1).sum()
    n_neg = (y == 0).sum()
    return n_neg / max(n_pos, 1)


def fit(X_train, y_train, X_val, y_val, params: dict | None = None,
        num_boost_round: int = 500, early_stopping_rounds: int = 30) -> lgb.Booster:
    params = {**DEFAULT_PARAMS, **(params or {})}
    params.setdefault("scale_pos_weight", compute_scale_pos_weight(y_train))

    train_set = lgb.Dataset(X_train, label=y_train)
    val_set = lgb.Dataset(X_val, label=y_val, reference=train_set)

    return lgb.train(
        params, train_set,
        num_boost_round=num_boost_round,
        valid_sets=[train_set, val_set],
        valid_names=["train", "val"],
        callbacks=[lgb.early_stopping(early_stopping_rounds), lgb.log_evaluation(50)],
    )


def save(model: lgb.Booster, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    model.save_model(path)


def load(path: str) -> lgb.Booster:
    return lgb.Booster(model_file=path)
