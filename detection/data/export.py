"""
Flat file export of feature_windows, for handoff to tooling outside this
repo's SQLite dependency (a separate training environment, sharing data
with a teammate, archiving a specific dataset version). Reads through
the same SQLAlchemy engine as extract.py, writes CSV plus a manifest
recording exactly what went into the file, so an export found later is
traceable back to the database state that produced it.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from detection.config import DATASETS_DIR, DB_PATH
from detection.data.extract import load_feature_windows


def export(entity_type: str, db_path: str = DB_PATH) -> Path:
    df = load_feature_windows(db_path, entity_type)
    if df.empty:
        raise SystemExit(f"[export] no rows for entity_type='{entity_type}', nothing to export")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"{entity_type}_{timestamp}"

    exports_dir = DATASETS_DIR / "exports"
    manifests_dir = DATASETS_DIR / "manifests"
    exports_dir.mkdir(parents=True, exist_ok=True)
    manifests_dir.mkdir(parents=True, exist_ok=True)

    csv_path = exports_dir / f"{stem}.csv"
    df.to_csv(csv_path, index=False)

    manifest = {
        "entity_type": entity_type,
        "db_path": str(db_path),
        "exported_at": timestamp,
        "row_count": len(df),
        "run_ids": sorted(int(r) for r in df.run_id.unique()),
        "feature_version": sorted(df["feature_version"].dropna().unique().tolist()),
        "aggregation_version": sorted(df["aggregation_version"].dropna().unique().tolist()),
        "csv_file": csv_path.name,
    }
    manifest_path = manifests_dir / f"{stem}.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"[export] wrote {len(df)} rows to {csv_path}")
    print(f"[export] manifest at {manifest_path}")
    return csv_path
