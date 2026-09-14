from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from observation import paths


def get_engine() -> Engine:
    paths.DATABASE_DIR.mkdir(parents=True, exist_ok=True)
    database_url = f"sqlite:///{paths.DATABASE_FILE.resolve().as_posix()}"
    engine = create_engine(database_url)

    @event.listens_for(engine, "connect")
    def configure_sqlite(dbapi_connection, _connection_record) -> None:
        dbapi_connection.execute("PRAGMA foreign_keys = ON")
        dbapi_connection.execute("PRAGMA journal_mode = WAL")

    return engine


def get_session() -> Session:
    return Session(get_engine())


@contextmanager
def connect() -> Iterator[Session]:
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def apply_migrations() -> None:
    """
    Brings the SQLite database up to the latest Alembic revision.
    Replaces the old hand-written .sql runner. Safe to call every time
    the pipeline starts, calling it when the database is already at
    head does nothing.
    """
    project_root = Path(__file__).resolve().parents[2]
    alembic_config = Config(str(project_root / "alembic.ini"))
    alembic_config.set_main_option(
        "script_location", str(project_root / "observation" / "database" / "alembic")
    )
    alembic_config.set_main_option(
        "sqlalchemy.url", f"sqlite:///{paths.DATABASE_FILE.resolve().as_posix()}"
    )
    command.upgrade(alembic_config, "head")