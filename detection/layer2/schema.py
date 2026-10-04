from __future__ import annotations

from collections import Counter

from observation.features.utils.entropy import shannon_entropy
from observation.features.utils.ip_utils import is_external_ip  # noqa: F401  (re-exported for builder.py)

# artifacts.py stores models under models/<entity_type>/<model_name>/<variant>.
GRAPH_ENTITY = "host_graph"
BASELINE_MODEL = "lightgbm"
BASELINE_VARIANT = "graph_stats"
GRAPH_SCHEMA_VERSION = "g2"

NODE_KINDS = ("host", "process", "remote_ip", "domain", "file", "port")
_BASE = len(NODE_KINDS)

COL_LOG_COUNT, COL_EXTERNAL, COL_ENTROPY, COL_LOG_LEN, COL_WELLKNOWN = range(_BASE, _BASE + 5)

NODE_FEATURE_NAMES = [f"is_{k}" for k in NODE_KINDS] + [
    "log_event_count", "is_external", "name_entropy", "log_name_length", "wellknown_port_ratio",
]


def resolve_model(model_name: str, variant: str, baseline: bool) -> tuple[str, str]:
    """--baseline means: the graph statistics LightGBM, stored under its own variant."""
    return (BASELINE_MODEL, BASELINE_VARIANT) if baseline else (model_name, variant)


def text_entropy(text: str) -> float:
    """Entropy of the characters of a name, using Layer 1's shannon_entropy."""
    return shannon_entropy(list(Counter(text).values())) if text else 0.0