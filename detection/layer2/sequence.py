"""
Turns the per window graph statistics into sequences: for window i, the last
`length` windows of the same run, oldest first. Only past windows are used,
because a live detector cannot see the future.
"""
from __future__ import annotations

import os

import numpy as np
import pandas as pd

from detection.layer2.baseline import stats_frame

SEQ_LENGTH = int(os.environ.get("SEQ_LENGTH", 6))


def make_sequences(stats: pd.DataFrame, index: pd.DataFrame, length: int = SEQ_LENGTH) -> np.ndarray:
    """Returns an array of shape (windows, length, statistics), aligned with `index`."""
    values = np.log1p(np.clip(stats.to_numpy(dtype=float), 0.0, None)).astype(np.float32)
    out = np.zeros((len(index), length, values.shape[1]), dtype=np.float32)
    times = pd.to_datetime(index["window_start_ts"], utc=True, format="ISO8601")

    for _, group in index.groupby("run_id"):
        positions = times.loc[group.index].sort_values().index.to_numpy()   # time order
        rows = values[positions]
        steps = np.arange(len(positions))
        for k in range(length):                                              # k = 0 is the oldest
            back = np.maximum(steps - (length - 1 - k), 0)                   # repeat the first window
            out[positions, k, :] = rows[back]
    return out


def dataset_sequences(ds, length: int = SEQ_LENGTH) -> np.ndarray:
    """Builds the sequences once per loaded dataset and reuses them."""
    cached = getattr(ds, "_sequences", None)
    if cached is None or cached[0] != length:
        cached = (length, make_sequences(stats_frame(ds.graphs), ds.index, length))
        ds._sequences = cached
    return cached[1]