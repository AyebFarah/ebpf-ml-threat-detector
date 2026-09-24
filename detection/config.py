import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DB_PATH = os.environ.get("OBSERVATION_DB_PATH", str(REPO_ROOT / "observation/database/merged_observations.db"))

MODELS_DIR = REPO_ROOT / "models"
EXPERIMENTS_DIR = REPO_ROOT / "experiments"
DATASETS_DIR = REPO_ROOT / "datasets"

RANDOM_SEED = 42

ENTITY_TYPES = ("flow", "host", "process")
