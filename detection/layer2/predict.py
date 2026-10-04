"""
Scoring and replay for Layer 2. One function, score_windows, knows which kind
of input each model family needs. Layer2Detector subclasses the existing
Detector and overrides only how a window is scored.
"""
from __future__ import annotations

import numpy as np

import detection.algorithms  # noqa: F401
import detection.layer2.model  # noqa: F401
import detection.layer2.seq_model  # noqa: F401
from detection import artifacts
from detection.config import DB_PATH
from detection.core.preprocessing import prepare
from detection.core.registry import family_of
from detection.data.extract import load_feature_windows
from detection.inference.detector import Detector
from detection.layer2.baseline import stats_frame
from detection.layer2.dataset import load_graphs
from detection.layer2.schema import BASELINE_VARIANT, GRAPH_ENTITY, resolve_model
from detection.layer2.sequence import dataset_sequences
from detection.replay.output import JsonlSink
from detection.replay.runner import replay_run


def score_graphs(bundle, graphs):
    """The baseline eats a table of statistics, the GNN eats graphs."""
    if bundle.variant == BASELINE_VARIANT:
        return bundle.model.predict_proba(prepare(stats_frame(graphs), bundle.feature_cols))
    return bundle.model.predict_proba(graphs)


def score_windows(bundle, ds, positions):
    """Scores the windows at these dataset positions with any Layer 2 model."""
    if bundle.variant != BASELINE_VARIANT and family_of(bundle.model_name) == "sequence":
        return bundle.model.predict_proba(dataset_sequences(ds)[np.asarray(positions, dtype=int)])
    return score_graphs(bundle, ds.subset(positions))


class Layer2Detector(Detector):
    def __init__(self, bundle, ds):
        super().__init__(bundle)
        self.ds = ds
        self.position = {int(w): i for i, w in enumerate(ds.index["window_id"])}

    def score(self, window: dict) -> float:
        pos = self.position[int(window["id"])]
        return float(score_windows(self.bundle, self.ds, [pos])[0])


def replay(run_id: int, model_name: str, variant: str, baseline: bool, speed: float = 10.0,
           db_path=DB_PATH, output: str | None = None) -> dict:
    model_name, variant = resolve_model(model_name, variant, baseline)
    ds = load_graphs()
    df = load_feature_windows(db_path, "host")
    df = df[(df.run_id == run_id) & df["id"].isin(ds.index["window_id"])]
    if df.empty:
        raise SystemExit(f"[layer2 replay] no host windows for run_id={run_id}")

    detector = Layer2Detector(artifacts.load_bundle(GRAPH_ENTITY, model_name, variant), ds)
    sink = JsonlSink(output) if output else None
    try:
        return replay_run(detector, df, speed, sink=sink)
    finally:
        if sink:
            sink.close()