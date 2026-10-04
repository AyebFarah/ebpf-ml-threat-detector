"""
Reads feature_windows rows via the same SQLAlchemy engine
observation.database.connection defines, so the pragmas it sets (foreign
keys, WAL) apply here too. This is the only module in detection/ that
should ever open a connection to a database file -- everything else in
detection/ works on the DataFrame this returns.

db_path is a required, explicit argument -- not silently defaulted --
on purpose: with several databases in play (observations.db,
attack_observations.db, merged_observations.db, ...), a report needs to
be able to state exactly which one produced a given result. Pass
detection.config.DB_PATH explicitly at call sites rather than relying on
an implicit default that could point somewhere unexpected.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd
from sqlalchemy import text

from observation.database.connection import get_engine


def load_feature_windows(db_path: str | Path, entity_type: str) -> pd.DataFrame:
    engine = get_engine(Path(db_path))
    try:
        df = pd.read_sql_query(
            text("SELECT * FROM feature_windows WHERE entity_type = :entity_type AND label IS NOT NULL"),
            engine, params={"entity_type": entity_type},
        )
    finally:
        engine.dispose()
    print(f"[extract] loaded {len(df)} '{entity_type}' rows from {db_path}")
    return df