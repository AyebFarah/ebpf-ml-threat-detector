import json
from pathlib import Path
from observation import paths
from observation.database.connection import connect, apply_migrations
from observation.database.repositories.runs import RunsRepository
from observation.database.repositories.correlated_events import CorrelatedEventsRepository
from observation.database.repositories.ssh_sessions import SshSessionsRepository


def _read_jsonl(path: Path) -> list:
    if not path.exists():
        return []
    records = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def load_into_database() -> int:
    apply_migrations()
    correlated_records = _read_jsonl(paths.CORRELATED_EVENTS_FILE)
    ssh_session_records = _read_jsonl(paths.SSH_SESSIONS_FILE)

    with connect() as conn:
        runs = RunsRepository(conn)
        run_id = runs.start_run()
        try:
            correlated_count = CorrelatedEventsRepository(conn).insert_many(run_id, correlated_records)
            ssh_count = SshSessionsRepository(conn).insert_many(run_id, ssh_session_records)
            runs.complete_run(
                run_id,
                correlated_events_count=correlated_count,
                ssh_sessions_count=ssh_count,
                source_correlated_file=str(paths.CORRELATED_EVENTS_FILE),
                source_ssh_sessions_file=str(paths.SSH_SESSIONS_FILE),
            )
        except Exception as exc:
            runs.fail_run(run_id, str(exc))
            raise

    print(f"[db] run {run_id}: inserted {correlated_count} correlated events "
          f"(with DNS/TLS/TCP/HTTP/file/privilege detail rows), "
          f"{ssh_count} ssh sessions -> {paths.DATABASE_FILE}")
    return run_id


if __name__ == "__main__":
    load_into_database()