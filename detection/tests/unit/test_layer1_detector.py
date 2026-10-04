import json
from dataclasses import asdict

import numpy as np

from detection.inference.detector import Detector

WINDOW = {"feat_a": 0.9, "feat_b": 1.0, "id": np.int64(3), "run_id": np.int64(7),
          "entity_type": "host", "entity_id": "H1", "window_start_ts": "2026-09-15T22:00:00Z",
          "window_end_ts": "2026-09-15T22:00:15Z", "label": np.int64(1), "attack_family": "port_scan"}


def test_window_above_threshold_raises_an_alert_that_can_be_saved_as_json(saved_dummy):
    alert = Detector.from_artifacts("host", "_dummy").process(WINDOW)
    assert alert is not None and alert.run_id == 7
    json.dumps(asdict(alert))   # raises TypeError if numpy integers leaked into the alert


def test_window_below_threshold_raises_no_alert(saved_dummy):
    assert Detector.from_artifacts("host", "_dummy").process({**WINDOW, "feat_a": 0.1}) is None


def test_missing_feature_values_do_not_crash_scoring(saved_dummy):
    assert Detector.from_artifacts("host", "_dummy").score({"feat_b": 1.0}) == 0.0