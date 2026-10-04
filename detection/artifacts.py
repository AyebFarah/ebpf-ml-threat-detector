from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from detection.config import DEFAULT_VARIANT, MODELS_DIR

if TYPE_CHECKING:
    from detection.core.base_model import BaseDetectionModel

METRICS_FILE = "metrics.json"
SCHEMA_FILE = "feature_schema.json"
SPLIT_FILE = "split.json"
EVALUATION_FILE = "evaluation.json"


@dataclass(frozen=True)
class TrainedModel:
    """Everything needed to score data with one trained model."""
    entity_type: str
    model_name: str
    variant: str
    model: "BaseDetectionModel"
    feature_cols: list[str]
    threshold: float
    meta: dict


def model_dir(entity_type: str, model_name: str, variant: str = DEFAULT_VARIANT,
              create: bool = False) -> Path:
    path = MODELS_DIR / entity_type / model_name / variant
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def metrics_path(entity_type, model_name, variant=DEFAULT_VARIANT) -> Path:
    return model_dir(entity_type, model_name, variant) / METRICS_FILE


def list_trained_models(entity_type: str, variant: str = DEFAULT_VARIANT) -> list[str]:
    base = MODELS_DIR / entity_type
    if not base.exists():
        return []
    return sorted(p.name for p in base.iterdir() if (p / variant / METRICS_FILE).exists())


def _write_json(path: Path, payload: dict) -> None:
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


def _read_json(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def save_bundle(entity_type: str, model_name: str, variant: str, model: "BaseDetectionModel",
                feature_cols: list[str], threshold: float, metrics: dict, params: dict | None,
                db_path, split_info: dict) -> Path:
    directory = model_dir(entity_type, model_name, variant, create=True)
    filename = type(model).artifact_filename
    model.save(str(directory / filename))

    _write_json(directory / METRICS_FILE, {
        "entity_type": entity_type, "model_name": model_name, "variant": variant,
        "db_path": str(db_path), "threshold": threshold, "params": params or {},
        "metrics": metrics, "artifact_filename": filename,
    })
    _write_json(directory / SCHEMA_FILE, {
        "entity_type": entity_type, "feature_columns": feature_cols,
        "feature_count": len(feature_cols),
    })
    _write_json(directory / SPLIT_FILE, split_info)
    return directory / filename


def load_bundle(entity_type: str, model_name: str, variant: str = DEFAULT_VARIANT) -> TrainedModel:
    import detection.algorithms  # noqa: F401  (registers every algorithm)
    from detection.core.registry import get_model_class

    directory = model_dir(entity_type, model_name, variant)
    if not (directory / METRICS_FILE).exists():
        raise FileNotFoundError(
            f"No trained model at {directory}. Train it first: "
            f"python -m detection.cli train --entity-type {entity_type} "
            f"--model {model_name} --variant {variant}"
        )
    meta = _read_json(directory / METRICS_FILE)
    cols = _read_json(directory / SCHEMA_FILE)["feature_columns"]
    model = get_model_class(model_name).load(str(directory / meta["artifact_filename"]))
    return TrainedModel(entity_type, model_name, variant, model, cols, meta["threshold"], meta)


def load_split(entity_type: str, model_name: str, variant: str = DEFAULT_VARIANT) -> dict:
    return _read_json(model_dir(entity_type, model_name, variant) / SPLIT_FILE)

def save_evaluation(entity_type: str, model_name: str, variant: str, payload: dict) -> Path:
    path = model_dir(entity_type, model_name, variant) / EVALUATION_FILE
    _write_json(path, payload)
    return path

def load_evaluation(entity_type: str, model_name: str, variant: str = DEFAULT_VARIANT) -> dict:
    return _read_json(model_dir(entity_type, model_name, variant) / EVALUATION_FILE)

def promote(entity_type: str, model_name: str, variant: str, to: str = DEFAULT_VARIANT) -> None:
    if variant == to:
        return
    src = model_dir(entity_type, model_name, variant)
    dst = model_dir(entity_type, model_name, to, create=True)
    for item in src.iterdir():
        if item.is_file():
            shutil.copy2(item, dst / item.name)
    print(f"[artifacts] promoted {entity_type}/{model_name}/{variant} to {entity_type}/{model_name}/{to}")