from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from detection import artifacts
from detection.config import DEFAULT_VARIANT, REPORTS_DIR


def write_report(entity_type: str, model_name: str, variant: str = DEFAULT_VARIANT,
                 overhead: dict | None = None, output_path: Path | None = None) -> Path:
    meta = json.loads(artifacts.metrics_path(entity_type, model_name, variant).read_text())

    lines = ["# Detection pipeline report",
             f"generated: {datetime.now(timezone.utc).isoformat()}",
             f"entity type: {entity_type}, model: {model_name}, variant: {variant}",
             f"threshold: {meta['threshold']:.3f}", ""]
    for split, m in meta.get("metrics", {}).items():
        lines.append(f"* {split}: ROC AUC={m.get('roc_auc')}, PR AUC={m.get('pr_auc')}, "
                     f"precision={m.get('precision'):.3f}, recall={m.get('recall'):.3f}")
    if overhead:
        lines += ["", "## Latency",
                  f"* {overhead['mean_ms_per_window']:.4f} ms per window "
                  f"({overhead['windows_per_sec']:.0f} windows per second)"]

    output_path = output_path or REPORTS_DIR / f"report_{entity_type}_{model_name}_{datetime.now():%Y%m%d_%H%M%S}.md"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines))
    print(f"[reports] wrote {output_path}")
    return output_path