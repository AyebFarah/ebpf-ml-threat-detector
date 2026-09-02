"""Feature engineering pipeline: builds feature_windows rows from
correlated_events. See docs/011-feature-engineering-v1.md for feature
definitions and docs/012-feature-pipeline.md for operations.
"""

from .extractor import build_feature_windows, parse_label
from .baseline import build_ja4_baseline
from .config import FEATURE_VERSION, AGGREGATION_VERSION

__all__ = [
    "build_feature_windows",
    "parse_label",
    "build_ja4_baseline",
    "FEATURE_VERSION",
    "AGGREGATION_VERSION",
]