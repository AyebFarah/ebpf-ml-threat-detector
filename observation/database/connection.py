from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from observation import paths

from sqlalchemy import create_engine, event, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from observation import paths
from observation.database.models import SchemaMigration


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


def _migration_statements(script: str) -> Iterator[str]:
    for statement in script.split(";"):
        if statement.strip():
            yield statement


def apply_migrations() -> None:
    engine = get_engine()
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version TEXT PRIMARY KEY, "
            "applied_at TEXT NOT NULL DEFAULT (datetime('now')))"
        ))
        applied = set(connection.execute(select(SchemaMigration.version)).scalars())
        for migration_file in sorted(paths.MIGRATIONS_DIR.glob("*.sql")):
            version = migration_file.stem
            if version in applied:
                continue
            conn.executescript(migration_file.read_text(encoding="utf-8"))
            conn.execute("INSERT INTO schema_migrations (version) VALUES (?)", (version,))
            print(f"[db] applied migration: {version}")
