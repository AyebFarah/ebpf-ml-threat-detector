# SQLAlchemy Persistence Architecture

## 1. Overview

The observation pipeline stores telemetry and derived features in SQLite through
SQLAlchemy 2.x. Application code uses SQLAlchemy ORM models, sessions, and
expression-language statements instead of importing `sqlite3` or managing
cursors directly.

SQLite remains the storage engine. SQLAlchemy provides the persistence API and
keeps database access isolated from collectors, correlation logic, and feature
calculations.

## 2. Package structure

Database code is organized as follows:

```text
observation/database/
  connection.py        Engine, session, and migration lifecycle
  records.py           Input records that are not persisted ORM entities
  models/              One declarative ORM model per file
    base.py             Shared DeclarativeBase
    __init__.py         Public model exports
  repositories/        Persistence operations built with SQLAlchemy
  migrations/          Ordered SQLite schema migrations
  reports/             Read-only reporting queries
```

The classes in `records.py` represent normalized input passed into repositories.
They are deliberately separate from the mapped classes in `models/`.

## 3. Engine and session lifecycle

`observation.database.connection.connect()` is the transaction boundary used by
application code:

```python
from observation.database.connection import connect

with connect() as session:
    # repository and SQLAlchemy operations
    ...
```

The context manager:

1. Creates a SQLAlchemy `Session` bound to the SQLite database.
2. Commits when the block completes successfully.
3. Rolls back when an exception escapes the block.
4. Closes the session in all cases.

Each SQLite connection enables foreign-key enforcement and WAL journal mode.
Callers should not manually commit inside a `connect()` block unless they
intentionally need a separate transaction boundary.

## 4. ORM models

Every persisted entity has a dedicated model module. The mapped entities are:

- `ObservationRun`
- `CorrelatedEventModel`
- `ProcessObservation`
- `DnsObservation`
- `TlsObservation`
- `TcpFlowObservation`
- `HttpObservation`
- `FileActivityEvent`
- `PrivilegeActivityEvent`
- `SshSession`
- `TcpFlowRaw`
- `DnsEventRaw`
- `FeatureWindow`
- `AttackRunMetadata`
- `SchemaMigration`

`FeatureWindow` maps the complete feature table, including all traffic, DNS,
TLS, HTTP, process, privilege, file, and SSH feature columns.

Repositories accept a SQLAlchemy `Session`. Inserts, updates, deletes, joins,
and aggregates use ORM or SQLAlchemy Core statements. Query methods that are
consumed by the existing feature pipeline return mapping rows where convenient.

## 5. Relationships and deletion behavior

`ObservationRun` is the parent of correlated events, SSH sessions, raw TCP
flows, raw DNS events, feature windows, and optional attack metadata.

`CorrelatedEventModel` is the parent of process, DNS, TLS, TCP-flow, HTTP, file,
and privilege observations.

Relationships use `back_populates` in both directions. Parent relationships use
`delete-orphan` cascades, while foreign keys declare `ON DELETE CASCADE`. SQLite
foreign-key enforcement is enabled for every engine connection, so deleting a
run or correlated event also removes its dependent rows.

## 6. Indexes and uniqueness constraints

The ORM metadata declares all 31 indexes created by the current migration
files. Index names and composite-column order match the SQL schema exactly.

Important composite indexes include:

- `idx_correlated_events_run_timestamp` on `(run_id, timestamp)`
- `idx_feature_windows_entity` on `(entity_type, entity_id)`
- `idx_feature_windows_timestamp` on `(window_start_ts, window_end_ts)`

Raw TCP and DNS tables enforce uniqueness on `(run_id, dedup_key)`. Their
repositories use SQLite `ON CONFLICT DO NOTHING`, making repeated ingestion
idempotent without aborting the surrounding transaction.

Indexes are selected automatically by SQLite's query planner. Declaring them in
the ORM metadata does not force their use; it ensures schema metadata mirrors
the migration-defined database.

## 7. Schema migrations

`apply_migrations()` executes ordered `.sql` files from
`observation/database/migrations/`. Applied versions are recorded in
`schema_migrations`, and each migration runs inside a SQLAlchemy engine
transaction.

DDL migration statements use SQLAlchemy `text()` because they contain
SQLite-specific operations such as `ALTER TABLE`. Normal application queries do
not use the migration SQL runner.

The current migration mechanism is intentionally retained for compatibility
with existing databases. A future improvement is to adopt Alembic and convert
the existing migration history into versioned Alembic revisions.


## 8. Development guidance

- Use `connect()` for transaction ownership.
- Pass the resulting `Session` into repositories.
- Add one model file for every new table.
- Declare foreign keys, relationships, constraints, and indexes in the model.
- Add schema changes through a migration; do not modify an existing applied
  migration.
- Prefer `select()`, `insert()`, `update()`, and `delete()` expressions over raw
  SQL.
- Add integration coverage for new persistence behavior and migration upgrades.

Install project dependencies with:

```bash
python -m pip install -r requirements.txt
```

Run the test suite with:

```bash
python -m pytest -q
```
