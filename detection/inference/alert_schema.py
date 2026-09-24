"""
The Alert shape emitted by inference/detector.py and consumed by
replay/output.py. Kept as one dataclass so every layer/consumer agrees on the same fields.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Alert:
    window_id: int
    run_id: int
    entity_type: str
    entity_id: str
    window_start_ts: str
    window_end_ts: str
    layer: str          # "layer1", "layer2", "layer3" -- which layer raised this
    score: float
    true_label: int | None = None       # replay-only: ground truth from merged_observations.db
    attack_family: str | None = None    # replay-only: ground truth
    details: dict = field(default_factory=dict)  # e.g. {"rules_fired": [...]}, later layer3 summary text
