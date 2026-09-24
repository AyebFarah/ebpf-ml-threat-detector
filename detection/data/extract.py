"""
Reads feature_windows rows out of the SQLite database. This is the only
module that should ever open a connection to DB_PATH -- everything else
in detection/ works on the DataFrame this returns.
"""
from __future__ import annotations
from pathlib import Path

import pandas as pd
from sqlalchemy import select

from detection.config import DB_PATH
from observation.database.connection import connect
from observation.database.models import FeatureWindow


def load_feature_windows(entity_type: str, db_path: str = DB_PATH) -> pd.DataFrame:
    """Loads every feature_windows row for one entity_type ('flow',
    'host', or 'process'). Rows with label IS NULL shouldn't exist
    post-windowing, but are excluded defensively."""
    stmt = (select(FeatureWindow.__table__).where
        (       FeatureWindow.entity_type == entity_type,
                FeatureWindow.label.is_not(None),
        )
    )

    with connect(Path(db_path)) as session:
        return pd.read_sql(stmt, session.connection())
