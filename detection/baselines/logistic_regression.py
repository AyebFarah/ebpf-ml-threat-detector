"""
Logistic regression baseline -- a second point of comparison alongside
rules.py: how much does a linear model buy you over hand-written rules,
and how much does LightGBM buy you over a linear model. Trains on the
same feature_columns as Layer 1, with imputation + scaling since (unlike
LightGBM) sklearn's LogisticRegression can't handle NaNs on its own.
"""
from __future__ import annotations

import numpy as np
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

def build_pipeline() -> Pipeline:
    return Pipeline([
        ("impute", SimpleImputer(strategy="median")),
        ("scale", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])


def train(df_train, feature_cols) -> Pipeline:
    pipe = build_pipeline()
    pipe.fit(df_train[feature_cols], df_train["label"])
    return pipe


def predict_proba(pipe: Pipeline, df, feature_cols) -> np.ndarray:
    return pipe.predict_proba(df[feature_cols])[:, 1]
