from __future__ import annotations

import json

import numpy as np
import pandas as pd

from detection.core.base_model import BaseDetectionModel
from detection.core.registry import register_model

RULES = {
    "port_scan": lambda r: (r.get("unique_dst_port_count") or 0) > 20
                           and (r.get("dst_port_entropy") or 0) > 3.0,
    "ssh_bruteforce": lambda r: (r.get("ssh_failure_ratio") or 0) > 0.7
                                and (r.get("ssh_attempt_count") or 0) > 5,
    "dns_tunneling": lambda r: (r.get("nxdomain_ratio") or 0) > 0.3
                               or (r.get("hex_like_ratio") or 0) > 0.5
                               or (r.get("base32_like_ratio") or 0) > 0.5,
    "high_connection_rate": lambda r: (r.get("connections_per_sec") or 0) > 10,
    "rare_tls_fingerprint": lambda r: (r.get("rare_ja4_ratio") or 0) > 0.8,
    "sensitive_file_after_privesc": lambda r: (r.get("sensitive_file_event_count") or 0) > 0
                                              and (r.get("sudo_exec_count") or 0) > 0,
}


@register_model("rules")
class RuleBasedModel(BaseDetectionModel):
    """Not trained. fit() is a no op. This exists so the hand written
    baseline compares against real models through the exact same
    evaluate.py path, instead of living in a separate special script."""
    name = "rules"
    artifact_filename = "model.json"

    def fit(self, X_train, y_train, X_val, y_val):
        return self

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        return X.apply(lambda row: 1.0 if any(rule(row.to_dict()) for rule in RULES.values()) else 0.0,
                       axis=1).to_numpy()

    def save(self, path):
        with open(path, "w") as f:
            json.dump({"type": "rules"}, f)

    @classmethod
    def load(cls, path):
        return cls()