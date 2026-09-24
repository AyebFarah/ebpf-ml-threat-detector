"""
Latency/throughput benchmarking for a trained detector -- the "measuring
... latency" half of the project brief's live-demo requirement. Run
separately from train.py/evaluate.py since it cares about wall-clock
timing, not accuracy, and you generally want to run it a few times / on
idle hardware to get a stable number.
"""
from __future__ import annotations
import time
import numpy as np
import pandas as pd


def benchmark_layer1(detector, df: pd.DataFrame, n_runs: int = 3) -> dict:
    """detector: a detection.layer1.predict.Layer1Detector (or anything
    with a .predict(dict) -> (bool, float) method). Scores rows one at a
    time, which is the realistic shape for a live pipeline (one window
    arrives, gets scored, next arrives) rather than a batch matrix."""
    windows = df.to_dict("records")
    per_run_ms = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        for w in windows:
            detector.predict(w)
        per_run_ms.append((time.perf_counter() - t0) * 1000)

    total_windows = len(windows)
    mean_total_ms = float(np.mean(per_run_ms))
    return {
        "n_windows": total_windows,
        "n_runs": n_runs,
        "mean_total_ms": mean_total_ms,
        "mean_ms_per_window": mean_total_ms / max(total_windows, 1),
        "windows_per_sec": total_windows / (mean_total_ms / 1000) if total_windows and mean_total_ms else 0.0,
    }
