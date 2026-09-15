from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_alembic_upgrade_head_builds_expected_tables(tmp_path):
    database_path = tmp_path / "fresh.db"
    project_root = Path(__file__).resolve().parents[3]

    alembic_config = Config(str(project_root / "alembic.ini"))
    alembic_config.set_main_option(
        "script_location", str(project_root / "observation" / "database" / "alembic")
    )
    alembic_config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")

    command.upgrade(alembic_config, "head")

    inspector = inspect(create_engine(f"sqlite:///{database_path}"))
    tables = set(inspector.get_table_names())

    for expected_table in ("observation_runs", "correlated_events", "feature_windows"):
        assert expected_table in tables