from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from observation.database.models import Base


@pytest.fixture()
def engine(tmp_path):
    database_path = tmp_path / "test_observations.db"

    test_engine = create_engine(
        f"sqlite:///{database_path}"
    )

    Base.metadata.create_all(test_engine)

    yield test_engine

    test_engine.dispose()


@pytest.fixture()
def session(engine):
    with Session(engine) as db_session:
        yield db_session