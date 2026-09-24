"""
Layer 1 real-time inference wrapper. Loads the trained model once, the
live pipeline (replay or, eventually, a real eBPF-driven runner) holds
one Layer1Detector instance and calls .predict() per incoming flow-level
window, rather than reloading the model on every call.
"""
from __future__ import annotations

import json

import numpy as np

from detection.inference.thresholds import THRESHOLDS
from detection.layer1 import model as layer1_model


def load_tuned_threshold(metrics_path: str, fallback: float | None = None) -> float:
    """Reads the threshold layer1/train.py tuned on its validation split
    and saved into metrics.json. Prefer this over THRESHOLDS['layer1']
    (a static fallback) wherever a metrics.json from an actual training
    run is available, see evaluation.metrics.find_best_threshold for
    why a fixed 0.5 isn't safe to assume."""
    try:
        with open(metrics_path) as f:
            return json.load(f)["threshold"]
    except (FileNotFoundError, KeyError):
        return fallback if fallback is not None else THRESHOLDS["layer1"]


class Layer1Detector:
    def __init__(self, model_path: str, feature_cols: list[str], threshold: float | None = None):
        self.model = layer1_model.load(model_path)
        self.feature_cols = feature_cols
        self.threshold = threshold if threshold is not None else THRESHOLDS["layer1"]

    def score(self, window: dict) -> float:
        x = np.array([[window.get(c) for c in self.feature_cols]], dtype=float)
        return float(self.model.predict(x)[0])

    def predict(self, window: dict) -> tuple[bool, float]:
        p = self.score(window)
        return p >= self.threshold, p
