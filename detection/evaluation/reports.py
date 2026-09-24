"""
Turns the JSON metrics files that train.py / evaluate.py / overhead.py
produce into one readable markdown report under experiments/reports/.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from detection.config import EXPERIMENTS_DIR


def write_report(layer1_metrics_path: str, overhead: dict | None = None,
                 rule_baseline_metrics: dict | None = None,
                 output_path: str | None = None) -> str:
    with open(layer1_metrics_path) as f:
        layer1 = json.load(f)

    lines = ["# Detection pipeline report",
             f"generated: {datetime.now(timezone.utc).isoformat()}",
             "", "## Layer 1 (LightGBM)"]
    for split, m in layer1.get("metrics", {}).items():
        lines.append(f"- **{split}**: ROC-AUC={m.get('roc_auc')}, PR-AUC={m.get('pr_auc')}")

    if overhead:
        lines += ["", "## Latency",
                  f"- {overhead['mean_ms_per_window']:.4f} ms/window "
                  f"({overhead['windows_per_sec']:.0f} windows/sec)"]

    if rule_baseline_metrics:
        lines += ["", "## Rule-based baseline (comparison)"]
        for split, m in rule_baseline_metrics.items():
            lines.append(f"- **{split}**: {m}")

    output_path = output_path or str(
        EXPERIMENTS_DIR / "reports" / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    )
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text("\n".join(lines))
    print(f"[reports] wrote {output_path}")
    return output_path
