from __future__ import annotations

import detection.algorithms  # noqa: F401
from detection.config import DB_PATH, DEFAULT_METRIC
from detection.core.registry import available_models
from detection.training.train import run as train_run

COMPARE_VARIANT = "compare"


def run(entity_type: str, db_path=DB_PATH, models: list[str] | None = None) -> dict:
    results = {}
    for name in models or available_models():
        try:
            results[name] = train_run(entity_type, model_name=name, db_path=db_path,
                                      variant=COMPARE_VARIANT)
        except Exception as exc:  # one broken algorithm must not stop the comparison
            print(f"[compare] {name} skipped: {exc!r}")
    return results


def summarize(results: dict, metric: str = DEFAULT_METRIC, split: str = "val") -> list[tuple]:
    rows = []
    for name, result in results.items():
        value = result["metrics"].get(split, {}).get(metric)
        rows.append((name, value))
    rows.sort(key=lambda kv: (kv[1] is not None, kv[1] or 0.0), reverse=True)

    print(f"\n[compare] ranking by {metric} on {split}")
    for rank, (name, value) in enumerate(rows, start=1):
        shown = "undefined" if value is None else f"{value:.4f}"
        print(f"  {rank}. {name:<28} {shown}")
    return rows