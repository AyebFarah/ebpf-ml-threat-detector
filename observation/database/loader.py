import json
import time
from pathlib import Path
from .. import paths
from .connection import connect, apply_migrations
from .repositories.runs import RunsRepository
from .repositories.correlated_events import CorrelatedEventsRepository
from .repositories.ssh_sessions import SshSessionsRepository
from .repositories.tcp_flows_raw import TcpFlowsRawRepository
from .repositories.dns_events_raw import DnsEventsRawRepository


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


def load_into_database(scenario, label="benign", notes=None, duration_ms=None,
                       capture_start_ts=None, capture_end_ts=None):
    apply_migrations()
    correlated_records = _read_jsonl(paths.CORRELATED_EVENTS_FILE)
    ssh_session_records = _read_jsonl(paths.SSH_SESSIONS_FILE)
    tcp_flow_records = _read_jsonl(paths.TCP_EVENTS_FILE)
    dns_event_records = _read_jsonl(paths.DNS_EVENTS_FILE)

    is_attack = label.startswith("attack:")
    status = "awaiting_metadata" if is_attack else "completed"

    with connect() as conn:
        run_id = RunsRepository(conn).start_run(
            scenario=scenario, label=label, notes=notes,
            started_at=capture_start_ts,
        )

    try:
        with connect() as conn:
            correlated_count = CorrelatedEventsRepository(conn).insert_many(run_id, correlated_records)
            ssh_count = SshSessionsRepository(conn).insert_many(run_id, ssh_session_records)
            tcp_flow_raw_count = TcpFlowsRawRepository(conn).insert_many(run_id, tcp_flow_records)
            dns_raw_count = DnsEventsRawRepository(conn).insert_many(run_id, dns_event_records)
            RunsRepository(conn).complete_run(
                run_id, correlated_events_count=correlated_count, ssh_sessions_count=ssh_count,
                source_correlated_file=str(paths.CORRELATED_EVENTS_FILE),
                source_ssh_sessions_file=str(paths.SSH_SESSIONS_FILE),
                duration_ms=duration_ms, status=status,
                ended_at=capture_end_ts,
            )
    except Exception as exc:
        with connect() as conn:
            RunsRepository(conn).fail_run(run_id, str(exc))
        raise

    print(f"[db] run {run_id} ({scenario}/{label}): inserted {correlated_count} correlated events "
          f"(with DNS/TLS/TCP/HTTP/file/privilege detail rows), "
          f"{ssh_count} ssh sessions, {tcp_flow_raw_count} raw tcp flows, {dns_raw_count} raw dns events -> {paths.DATABASE_FILE}")
    return run_id


if __name__ == "__main__":
    # manual/ad-hoc reload of existing jsonl into DB without rerunning the pipeline
    scenario = input("Scenario name: ").strip()
    label = input("Label [benign]: ").strip() or "benign"
    notes = input("Notes (optional): ").strip() or None
    load_into_database(scenario=scenario, label=label, notes=notes)