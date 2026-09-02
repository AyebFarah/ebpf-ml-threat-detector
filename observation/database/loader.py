import json
import time
from pathlib import Path
from .. import paths
from .connection import connect, apply_migrations
from .repositories.runs import RunsRepository
from .repositories.correlated_events import CorrelatedEventsRepository
from .repositories.ssh_sessions import SshSessionsRepository


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


def load_into_database(scenario: str, label: str = "benign",
                       notes: str | None = None,
                       duration_seconds: int | None = None) -> int:
    apply_migrations()
    correlated_records = _read_jsonl(paths.CORRELATED_EVENTS_FILE)
    ssh_session_records = _read_jsonl(paths.SSH_SESSIONS_FILE)

    with connect() as conn:
        runs = RunsRepository(conn)
        run_id = runs.start_run(scenario=scenario, label=label, notes=notes)
        try:
            correlated_count = CorrelatedEventsRepository(conn).insert_many(run_id, correlated_records)
            ssh_count = SshSessionsRepository(conn).insert_many(run_id, ssh_session_records)
            runs.complete_run(
                run_id,
                correlated_events_count=correlated_count,
                ssh_sessions_count=ssh_count,
                source_correlated_file=str(paths.CORRELATED_EVENTS_FILE),
                source_ssh_sessions_file=str(paths.SSH_SESSIONS_FILE),
                duration_seconds=duration_seconds,
            )
        except Exception as exc:
            runs.fail_run(run_id, str(exc))
            raise

    print(f"[db] run {run_id} ({scenario}/{label}): inserted {correlated_count} correlated events "
          f"(with DNS/TLS/TCP/HTTP/file/privilege detail rows), "
          f"{ssh_count} ssh sessions -> {paths.DATABASE_FILE}")
    return run_id


if __name__ == "__main__":
    # manual/ad-hoc reload of existing jsonl into DB without rerunning the pipeline
    scenario = input("Scenario name: ").strip()
    label = input("Label [benign]: ").strip() or "benign"
    notes = input("Notes (optional): ").strip() or None
    load_into_database(scenario=scenario, label=label, notes=notes)