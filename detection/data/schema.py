"""
Defines what a feature_windows row looks like from the detection
pipeline's point of view: which columns are model input, which are
labels/metadata, and which are non-numeric context reserved for later
layers (Layer 3) or future feature engineering.
"""
import pandas as pd

# Identifiers, labels, and bookkeeping metadata -- never model input.
NON_FEATURE_COLUMNS = {
    "id", "run_id", "window_start_ts", "window_end_ts", "entity_type", "entity_id",
    "label", "scenario", "attack_family", "attack_technique",
    "feature_version", "aggregation_version", "contributing_event_ids", "created_at",
}

# JSON-encoded distributions / free-text categorical hashes rather than
# plain numeric features. Layer 1 (tabular, tree-based) skips these for
# the MVP -- candidates for explicit feature engineering later (e.g.
# exploding tls_version_distribution into per-version ratios), or for
# Layer 3's contextual reasoning, which can read them as-is.
NON_NUMERIC_CONTEXT_COLUMNS = {
    "tls_version_distribution", "http_methods_distribution", "most_common_ja4",
}


def feature_columns(df: pd.DataFrame) -> list[str]:
    exclude = NON_FEATURE_COLUMNS | NON_NUMERIC_CONTEXT_COLUMNS
    return [c for c in df.columns if c not in exclude]

