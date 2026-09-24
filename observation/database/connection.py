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


def get_engine(database_file: Path | None = None) -> Engine:
    paths.DATABASE_DIR.mkdir(parents=True, exist_ok=True)
    target = (database_file or paths.DATABASE_FILE).resolve()
    database_url = f"sqlite:///{target.as_posix()}"
    engine = create_engine(database_url)

    @event.listens_for(engine, "connect")
    def configure_sqlite(dbapi_connection, _connection_record) -> None:
        dbapi_connection.execute("PRAGMA foreign_keys = ON")
        dbapi_connection.execute("PRAGMA journal_mode = WAL")

    return engine


def get_session(database_file: Path | None = None) -> Session:
    return Session(get_engine(database_file))


@contextmanager
def connect(database_file: Path | None = None) -> Iterator[Session]:
    session = get_session(database_file)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def alembic_config(database_file: Path | None = None) -> Config:
    project_root = Path(__file__).resolve().parents[2]
    target = (database_file or paths.DATABASE_FILE).resolve()
    config = Config(str(project_root / "alembic.ini"))
    config.set_main_option(
        "script_location", str(project_root / "observation" / "database" / "alembic")
    )
    config.set_main_option("sqlalchemy.url", f"sqlite:///{target.as_posix()}")
    return config


def apply_migrations(database_file: Path | None = None) -> None:
    """Brings the SQLite database up to the latest Alembic revision.
    Safe to call every time: when already at head it does nothing."""
    command.upgrade(alembic_config(database_file), "head")
