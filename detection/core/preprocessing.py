from __future__ import annotations

import pandas as pd


def prepare(df: pd.DataFrame, feature_cols: list[str]) -> pd.DataFrame:
    """
    Checks that every expected column exists (catches a stale feature
    list or a renamed column loudly instead of producing silent
    garbage predictions), then coerces everything to numeric.

    This stays deliberately thin. Model specific handling (LightGBM
    tolerates missing values natively, XGBoost needs a fill value,
    scikit learn needs imputing and scaling) lives inside each model's
    own fit/predict_proba, because only that model knows what it needs.
    """
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Missing feature columns: {missing}")

    result = df.loc[:, feature_cols].copy()
    for column in feature_cols:
        result[column] = pd.to_numeric(result[column], errors="coerce")
    return result