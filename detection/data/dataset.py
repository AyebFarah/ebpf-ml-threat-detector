"""
Reads an exported CSV back into a DataFrame. Notebooks use this so they work on a
frozen snapshot: the same file gives the same numbers tomorrow, even if the database changes.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from detection.config import EXPORTS_DIR, MANIFESTS_DIR


def latest_export(entity_type: str) -> Path:
    # The timestamp in the file name sorts alphabetically in time order.
    files = sorted(EXPORTS_DIR.glob(f"{entity_type}_*.csv"))
    if not files:
        raise FileNotFoundError(
            f"No export for '{entity_type}' in {EXPORTS_DIR}. "
            f"Create one with: python -m detection.cli export --entity-type {entity_type}"
        )
    return files[-1]


def load_manifest(csv_path: Path) -> dict:
    manifest_path = MANIFESTS_DIR / f"{Path(csv_path).stem}.json"
    return json.loads(manifest_path.read_text()) if manifest_path.exists() else {}


def load_export(entity_type: str, path: str | Path | None = None) -> tuple[pd.DataFrame, dict]:
    csv_path = Path(path) if path else latest_export(entity_type)
    df = pd.read_csv(csv_path, dtype={"attack_family": "string", "attack_technique": "string"})
    print(f"[dataset] loaded {len(df)} rows from {csv_path.name}")
    return df, load_manifest(csv_path)