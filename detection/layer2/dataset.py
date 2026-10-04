"""
Saves and loads a frozen snapshot of the graphs, the graph equivalent of
detection/data/export.py and dataset.py: the same file gives the same
numbers tomorrow, even if the database changes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import torch
from torch_geometric.data import Data

from detection.config import DATASETS_DIR

GRAPHS_DIR = DATASETS_DIR / "graphs"


@dataclass
class GraphDataset:
    graphs: list
    index: pd.DataFrame      # one row per graph, same order as graphs
    manifest: dict

    def subset(self, positions) -> list:
        return [self.graphs[int(i)] for i in positions]

    def by_window_id(self) -> dict:
        return dict(zip(self.index["window_id"].astype(int), self.graphs))


def save_snapshot(graphs: list, index: pd.DataFrame, extra: dict) -> Path:
    GRAPHS_DIR.mkdir(parents=True, exist_ok=True)
    stem = f"host_graphs_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
    payload = [{"x": g.x, "edge_index": g.edge_index, "y": g.y} for g in graphs]
    torch.save(payload, GRAPHS_DIR / f"{stem}.pt")
    index.to_csv(GRAPHS_DIR / f"{stem}.csv", index=False)
    manifest = {
        "file": f"{stem}.pt", "graph_count": len(graphs),
        "run_ids": sorted(int(r) for r in index.run_id.unique()), **extra,
    }
    (GRAPHS_DIR / f"{stem}.json").write_text(json.dumps(manifest, indent=2))
    return GRAPHS_DIR / f"{stem}.pt"


def latest_snapshot() -> Path:
    files = sorted(GRAPHS_DIR.glob("host_graphs_*.pt"))   # timestamp sorts in time order
    if not files:
        raise FileNotFoundError(
            f"No graph snapshot in {GRAPHS_DIR}. Create one with: python -m detection.cli graph-build")
    return files[-1]


def load_graphs(path: str | Path | None = None) -> GraphDataset:
    pt = Path(path) if path else latest_snapshot()
    payload = torch.load(pt, weights_only=True)
    graphs = [Data(**item) for item in payload]
    index = pd.read_csv(pt.with_suffix(".csv"),
                        dtype={"attack_family": "string", "scenario": "string"})
    manifest_path = pt.with_suffix(".json")
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    print(f"[layer2 dataset] loaded {len(graphs)} graphs from {pt.name}")
    return GraphDataset(graphs, index, manifest)