from __future__ import annotations

import pandas as pd

from detection import artifacts
from detection.config import DEFAULT_VARIANT
from detection.evaluation.feature_groups import aggregate_importance_by_group


def compare(entity_type: str, models: list[str] | None = None,
            variant: str = DEFAULT_VARIANT) -> pd.DataFrame:
    names = models or artifacts.list_trained_models(entity_type, variant)
    rows = []
    for name in names:
        importances = artifacts.load_bundle(entity_type, name, variant).model.feature_importance()
        if not importances:
            print(f"[feature_importance] {name} has no feature_importance(), skipping")
            continue
        for group, pct in aggregate_importance_by_group(importances).items():
            rows.append({"model": name, "group": group, "importance_pct": pct})

    df = pd.DataFrame(rows)
    if df.empty:
        return df
    return df.pivot(index="group", columns="model", values="importance_pct").fillna(0.0)