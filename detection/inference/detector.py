from __future__ import annotations

import pandas as pd

from detection import artifacts
from detection.config import DEFAULT_VARIANT
from detection.core.preprocessing import prepare
from detection.inference.alert_schema import Alert


def _plain(value):
    """Turns numpy values and NaN into plain Python values so alerts can be saved as JSON."""
    if value is None or pd.isna(value):
        return None
    return value.item() if hasattr(value, "item") else value


class Detector:
    """One trained model, loaded once, scoring one window at a time."""

    def __init__(self, bundle: artifacts.TrainedModel):
        self.bundle = bundle

    @classmethod
    def from_artifacts(cls, entity_type: str, model_name: str,
                       variant: str = DEFAULT_VARIANT) -> "Detector":
        return cls(artifacts.load_bundle(entity_type, model_name, variant))

    def score(self, window: dict) -> float:
        cols = self.bundle.feature_cols
        row = pd.DataFrame([{c: window.get(c) for c in cols}], columns=cols)
        return float(self.bundle.model.predict_proba(prepare(row, cols))[0])

    def predict(self, window: dict) -> tuple[bool, float]:
        p = self.score(window)
        return p >= self.bundle.threshold, p

    def process(self, window: dict) -> Alert | None:
        is_attack, score = self.predict(window)
        if not is_attack:
            return None
        return Alert(
            window_id=_plain(window.get("id")), run_id=_plain(window.get("run_id")),
            entity_type=_plain(window.get("entity_type")), entity_id=_plain(window.get("entity_id")),
            window_start_ts=_plain(window.get("window_start_ts")),
            window_end_ts=_plain(window.get("window_end_ts")),
            layer=self.bundle.model_name, score=score,
            true_label=_plain(window.get("label")),
            attack_family=_plain(window.get("attack_family")),
            details={"threshold": self.bundle.threshold},
        )