"""
Where runner.py sends alerts: console by default, optionally a JSONL
file for later analysis (evaluation/reports.py, or just eyeballing what
fired).
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from detection.inference.alert_schema import Alert

def to_console(alert: Alert) -> None:
    correct = "" if alert.true_label is None else (
        " [correct]" if alert.true_label == 1 else " [FALSE POSITIVE]"
    )
    print(f"[alert] run={alert.run_id} {alert.entity_type}:{alert.entity_id} "
          f"{alert.layer} score={alert.score:.3f} family={alert.attack_family}{correct}")


class JsonlSink:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a")

    def write(self, alert: Alert) -> None:
        self._fh.write(json.dumps(asdict(alert)) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()
