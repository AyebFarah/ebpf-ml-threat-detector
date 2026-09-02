import pytest

from ... import paths
from ...database.connection import apply_migrations, connect
from ...database.repositories.runs import RunsRepository
from ...database.repositories.correlated_events import CorrelatedEventsRepository
from ...database.repositories.dns_observations import DnsObservationsRepository
from ...database.repositories.tls_observations import TlsObservationsRepository
from ...database.repositories.tcp_flow_observations import TcpFlowObservationsRepository
from ...database.repositories.http_observations import HttpObservationsRepository
from ...database.repositories.file_activity import FileActivityRepository


SAMPLE_RECORD = {
    "timestamp": "2026-08-21T10:00:00.000000000Z",
    "process": {"pid": 4242, "name": "/usr/bin/python3"},
    "process_context": {
        "exec_id": "node1:1:4242",
        "parent_exec_id": "node1:1:4241",
        "parent_binary": "/bin/bash",
        "arguments": "update.py",
        "uid": 0,
        "cwd": "/tmp",
    },
    "file_activity": [
        {
            "timestamp": "2026-08-21T10:00:01Z",
            "path": "/root/.ssh/authorized_keys",
            "operations": ["write"],
        }
    ],
    "privilege_activity": [],
    "network": {
        "src_ip": "10.0.0.5",
        "dst_ip": "93.184.216.34",
        "src_port": 51000,
        "dst_port": 443,
        "transport": "tcp",
        "direction": "outbound",
    },
    "dns": {
        "timestamp": "2026-08-21T09:59:59Z",
        "query_name": "example.com",
        "query_type": 1,
        "transaction_id": 42,
        "rcode": 0,
        "answer_count": 1,
        "resolved_ip": "93.184.216.34",
        "answers": [
            {
                "type": "A",
                "value": "93.184.216.34",
                "ttl": 300,
            }
        ],
    },
    "tls": {
        "timestamp": "2026-08-21T10:00:00.1Z",
        "sni": "example.com",
        "ja4": "t13d1517h2_8daaf6152771_806a8c22fdea",
    },
    "ssh": None,
    "tcp": {
        "start_ts": "2026-08-21T10:00:00Z",
        "end_ts": "2026-08-21T10:00:01Z",
        "duration_seconds": 1.0,
        "handshake_completed": True,
        "termination_reason": "fin",
        "packets_out": 10,
        "packets_in": 8,
        "bytes_out": 1500,
        "bytes_in": 3000,
        "retransmissions": 0,
    },
    "http": {
        "method": "GET",
        "host": "example.com",
        "path_hash": "abc123",
        "status_code": 200,
        "content_type": "text/html",
    },
    "correlation": {
        "dns_matched": True,
        "dns_method": "resolved_ip+time",
        "dns_time_delta_ms": 100,
        "tls_matched": True,
        "tls_method": "five_tuple",
        "tls_time_delta_ms": 50,
        "ssh_matched": False,
        "ssh_method": "src_ip+src_port+dst_port22+time",
        "ssh_time_delta_ms": None,
        "tcp_flow_matched": True,
        "tcp_flow_method": "five_tuple+start_ts",
        "tcp_flow_time_delta_ms": 5,
        "http_matched": True,
        "http_method": "five_tuple",
        "http_time_delta_ms": 500,
        "process_context_matched": True,
        "process_context_method": "pid+most_recent_exec_before_connect",
        "file_activity_count": 1,
        "file_activity_method": "pid+time_window",
        "privilege_activity_count": 0,
        "privilege_activity_method": "pid+time_window",
    },
}


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "DATABASE_DIR", tmp_path)
    monkeypatch.setattr(paths, "DATABASE_FILE", tmp_path / "observations.db")

    apply_migrations()

    yield


def test_migrations_create_all_nine_tables(db):
    with connect() as conn:
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

    expected = {
        "observation_runs",
        "correlated_events",
        "dns_observations",
        "tls_observations",
        "tcp_flow_observations",
        "http_observations",
        "file_activity_events",
        "privilege_activity_events",
        "ssh_sessions",
    }

    assert expected.issubset(tables)


def test_start_run_stores_metadata(db):
    with connect() as conn:
        run_id = RunsRepository(conn).start_run(
            scenario="browser_light",
            label="benign",
            notes="Chrome + YouTube",
        )

        row = conn.execute(
            """
            SELECT scenario, label, notes, duration_seconds
            FROM observation_runs
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()

        assert row["scenario"] == "browser_light"
        assert row["label"] == "benign"
        assert row["notes"] == "Chrome + YouTube"
        assert row["duration_seconds"] is None


def test_complete_run_stores_duration(db):
    with connect() as conn:
        runs = RunsRepository(conn)

        run_id = runs.start_run(
            scenario="browser_light",
            label="benign",
            notes="Chrome + YouTube",
        )

        runs.complete_run(
            run_id=run_id,
            correlated_events_count=10,
            ssh_sessions_count=0,
            duration_seconds=300,
        )

        row = conn.execute(
            """
            SELECT
                started_at,
                ended_at,
                status,
                duration_seconds
            FROM observation_runs
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()

        assert row["started_at"] is not None
        assert row["ended_at"] is not None
        assert row["status"] == "completed"
        assert row["duration_seconds"] == 300


def test_insert_creates_parent_and_all_child_rows(db):
    with connect() as conn:
        run_id = RunsRepository(conn).start_run(
            scenario="test",
            label="benign",
        )

        count = CorrelatedEventsRepository(conn).insert_many(
            run_id,
            [SAMPLE_RECORD],
        )

        assert count == 1

        parent = conn.execute(
            """
            SELECT *
            FROM correlated_events
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()

        # Core table has NO TLS/DNS/HTTP detail columns.
        # Verify the hybrid split.
        assert "sni" not in parent.keys()
        assert parent["tls_matched"] == 1
        assert parent["dns_matched"] == 1

        dns_rows = DnsObservationsRepository(conn).for_correlated_event(
            parent["id"]
        )

        assert len(dns_rows) == 1
        assert dns_rows[0]["query_name"] == "example.com"
        assert dns_rows[0]["resolved_ip"] == "93.184.216.34"

        tls_rows = TlsObservationsRepository(conn).for_correlated_event(
            parent["id"]
        )

        assert len(tls_rows) == 1
        assert tls_rows[0]["sni"] == "example.com"
        assert (
                tls_rows[0]["ja4"]
                == "t13d1517h2_8daaf6152771_806a8c22fdea"
        )

        tcp_rows = TcpFlowObservationsRepository(conn).for_correlated_event(
            parent["id"]
        )

        assert len(tcp_rows) == 1
        assert tcp_rows[0]["bytes_in"] == 3000

        http_rows = HttpObservationsRepository(conn).for_correlated_event(
            parent["id"]
        )

        assert len(http_rows) == 1
        assert http_rows[0]["status_code"] == 200

        file_rows = FileActivityRepository(conn).for_correlated_event(
            parent["id"]
        )

        assert len(file_rows) == 1
        assert file_rows[0]["path"] == "/root/.ssh/authorized_keys"


def test_no_dns_block_produces_no_dns_observation_row(db):
    record = dict(SAMPLE_RECORD, dns=None)

    with connect() as conn:
        run_id = RunsRepository(conn).start_run(
            scenario="test",
            label="benign",
        )

        CorrelatedEventsRepository(conn).insert_many(
            run_id,
            [record],
        )

        parent = conn.execute(
            """
            SELECT *
            FROM correlated_events
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()

        dns_rows = DnsObservationsRepository(conn).for_correlated_event(
            parent["id"]
        )

        assert dns_rows == []


def test_feature_query_needs_no_joins_for_core_flags(db):
    """
    The whole point of the hybrid design: a common ML feature query
    reads straight off correlated_events, no joins required.
    """
    with connect() as conn:
        run_id = RunsRepository(conn).start_run(
            scenario="test",
            label="benign",
        )

        CorrelatedEventsRepository(conn).insert_many(
            run_id,
            [SAMPLE_RECORD],
        )

        row = conn.execute(
            """
            SELECT
                dns_matched,
                tls_matched,
                tcp_flow_matched,
                http_matched,
                dns_time_delta_ms,
                tls_time_delta_ms
            FROM correlated_events
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()

        assert row["dns_matched"] == 1
        assert row["tls_time_delta_ms"] == 50