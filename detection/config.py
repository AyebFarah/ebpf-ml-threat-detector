from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DB_PATH = Path(os.environ.get(
    "OBSERVATION_DB_PATH",
    REPO_ROOT / "observation" / "database" / "merged_observations.db",
    ))

MODELS_DIR = REPO_ROOT / "models"
EXPERIMENTS_DIR = REPO_ROOT / "experiments"
REPORTS_DIR = EXPERIMENTS_DIR / "reports"
DATASETS_DIR = REPO_ROOT / "datasets"
EXPORTS_DIR = DATASETS_DIR / "exports"
MANIFESTS_DIR = DATASETS_DIR / "manifests"
FIGURES_DIR = REPORTS_DIR / "figures"

RANDOM_SEED = int(os.environ.get("RANDOM_SEED", 42))
ENTITY_TYPES = ("flow", "host", "process")

DEFAULT_VARIANT = "default"
DEFAULT_MODEL = "lightgbm"
DEFAULT_METRIC = "pr_auc"