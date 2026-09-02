import sqlite3
from contextlib import contextmanager
from .. import paths


def _configure(conn: sqlite3.Connection) -> None:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")


def get_connection() -> sqlite3.Connection:
    paths.DATABASE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(paths.DATABASE_FILE)
    _configure(conn)
    return conn


@contextmanager
def connect():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _applied_migrations(conn: sqlite3.Connection) -> set:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "version TEXT PRIMARY KEY, "
        "applied_at TEXT NOT NULL DEFAULT (datetime('now')))"
    )
    rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
    return {row["version"] for row in rows}


def apply_migrations() -> None:
    with connect() as conn:
        applied = _applied_migrations(conn)
        for migration_file in sorted(paths.MIGRATIONS_DIR.glob("*.sql")):
            version = migration_file.stem
            if version in applied:
                continue
            conn.executescript(migration_file.read_text(encoding="utf-8"))
            conn.execute("INSERT INTO schema_migrations (version) VALUES (?)", (version,))
            print(f"[db] applied migration: {version}")