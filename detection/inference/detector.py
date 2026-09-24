"""
Ties the layers together into one object the replay runner calls per incoming window. Currently wraps Layer 1 only
"""
from __future__ import annotations

from detection.inference.alert_schema import Alert
from detection.layer1.predict import Layer1Detector


class TieredDetector:
    def __init__(self, layer1: Layer1Detector):
        self.layer1 = layer1

    def process(self, window: dict) -> Alert | None:
        is_attack, score = self.layer1.predict(window)
        if not is_attack:
            return None
        return Alert(
            window_id=window.get("id"),
            run_id=window.get("run_id"),
            entity_type=window.get("entity_type"),
            entity_id=window.get("entity_id"),
            window_start_ts=window.get("window_start_ts"),
            window_end_ts=window.get("window_end_ts"),
            layer="layer1",
            score=score,
            true_label=window.get("label"),
            attack_family=window.get("attack_family"),
        )
