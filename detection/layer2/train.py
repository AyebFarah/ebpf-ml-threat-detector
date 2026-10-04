from __future__ import annotations

import detection.algorithms  # noqa: F401  (registers the tabular models)
import detection.layer2.model  # noqa: F401  (registers graphsage and gcn)
import detection.layer2.seq_model  # noqa: F401  (registers gru, lstm, cnn)
from detection.core.registry import family_of, get_model_class
from detection.layer2.sequence import dataset_sequences
from detection import artifacts
from detection.config import DB_PATH, DEFAULT_VARIANT, RANDOM_SEED
from detection.core.preprocessing import prepare
from detection.core.registry import get_model_class
from detection.evaluation.metrics import evaluate_scores, find_best_threshold
from detection.layer2.baseline import STAT_COLUMNS, stats_frame
from detection.layer2.dataset import load_graphs
from detection.layer2.schema import GRAPH_ENTITY, NODE_FEATURE_NAMES, resolve_model
from detection.layer2.split import run_ids_of, split_positions
from detection.training.train import _print_summary


def run(model_name: str = "graphsage", variant: str = DEFAULT_VARIANT, baseline: bool = False,
        db_path=DB_PATH, params: dict | None = None) -> dict:
    model_name, variant = resolve_model(model_name, variant, baseline)
    print(f"[layer2 train] {GRAPH_ENTITY} / {model_name} / {variant}")

    ds = load_graphs()
    positions = dict(zip(("train", "val", "test"), split_positions(ds.index)))
    if len(positions["train"]) == 0 or len(positions["val"]) == 0:
        raise SystemExit("[layer2 train] train or val split is empty, not enough runs")
    for name, pos in positions.items():
        part = ds.index.iloc[pos]
        print(f"[layer2 train] {name}: {len(part)} graphs, {part.run_id.nunique()} runs")

    labels = {name: ds.index["label"].iloc[pos] for name, pos in positions.items()}

    family = "tabular" if baseline else family_of(model_name)
    if family == "tabular":
        cols = STAT_COLUMNS
        def make_inputs(pos):
            return prepare(stats_frame(ds.subset(pos)), cols)
    elif family == "sequence":
        cols = STAT_COLUMNS
        sequences = dataset_sequences(ds)
        def make_inputs(pos):
            return sequences[pos]
    else:
        cols = NODE_FEATURE_NAMES
        make_inputs = ds.subset

    inputs = {name: make_inputs(pos) for name, pos in positions.items() if len(pos)}

    model = get_model_class(model_name)(params=params)
    model.fit(inputs["train"], labels["train"], inputs["val"], labels["val"])

    val_scores = model.predict_proba(inputs["val"])
    threshold = find_best_threshold(labels["val"], val_scores, metric="f1")
    metrics = {name: evaluate_scores(labels[name], model.predict_proba(X), split_name=name,
                                     threshold=threshold, verbose=False)
               for name, X in inputs.items()}
    _print_summary({name: ds.index.iloc[positions[name]] for name in inputs}, metrics, threshold)

    saved_params = {**(model.params or {}), "graph_snapshot": ds.manifest.get("file")}
    path = artifacts.save_bundle(
        GRAPH_ENTITY, model_name, variant, model, list(cols), threshold, metrics, saved_params,
        db_path,
        split_info={
            "random_state": RANDOM_SEED, "group_column": "run_id",
            "train_run_ids": run_ids_of(ds.index, positions["train"]),
            "val_run_ids": run_ids_of(ds.index, positions["val"]),
            "test_run_ids": run_ids_of(ds.index, positions["test"]),
        },
    )
    print(f"[layer2 train] model saved to {path}")

    importances = model.feature_importance()
    if importances:
        print("[layer2 train] top 5 graph statistics by importance:")
        for name, score in sorted(importances.items(), key=lambda kv: kv[1], reverse=True)[:5]:
            print(f"  {name}: {score:.1f}")
    return {"model": model, "threshold": threshold, "metrics": metrics}