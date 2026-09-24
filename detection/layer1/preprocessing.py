"""
Layer 1 feature preprocessing. LightGBM handles missing values and
doesn't need scaling, so this is intentionally thin, it exists
as the seam to add things like feature clipping, log-transforms for
heavy-tailed columns (byte counts, durations), or a fixed column-order
guarantee, without touching train.py or predict.py.
"""
from __future__ import annotations
import pandas as pd


def prepare(df: pd.DataFrame, feature_cols: list[str]) -> pd.DataFrame:
    return df[feature_cols]
