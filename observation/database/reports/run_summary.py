"""Usage: python3 -m observation.database.reports.run_summary <run_id>"""
import sys
import re
import json
import os
from sqlalchemy import case, func, select
from observation.database.connection import connect
from observation.database.models.observation_run import ObservationRun
from observation.database.models.correlated_event import CorrelatedEventModel
from observation.database.models.ssh_session import SshSession
from observation.database.models.attack_run_metadata import AttackRunMetadata
from observation.database.models.tcp_flow_raw import TcpFlowRaw
from observation.database.models.dns_event_raw import DnsEventRaw
from observation import paths

SUMMARY_FILE = paths.RUN_SUMMARY_FILE


TUNNEL_NAME = re.compile(r"^[a-z2-7]{16,63}\.[a-z0-9.-]+$")
EXPECTED_DNS_QUERIES = {"low": 50, "medium": 200, "high": 800}   # per repetition, from dns_tunneling.sh


def dns_content_check(conn, run_id, meta) -> list[str]:
    """Checks the CONTENT of a dns_tunneling run, not only that it finished."""
    names = conn.execute(select(DnsEventRaw.query_name).where(
        DnsEventRaw.run_id == run_id, DnsEventRaw.event_type == "dns_query"
    )).scalars().all()
    responses = conn.scalar(select(func.count()).select_from(DnsEventRaw).where(
        DnsEventRaw.run_id == run_id, DnsEventRaw.event_type == "dns_response"))
    params = json.loads(meta["parameters"]) if meta.get("parameters") else {}
    reps = params.get("repetitions")
    per_rep = EXPECTED_DNS_QUERIES.get(meta.get("intensity"))
    expected = reps * per_rep if reps and per_rep else None
    bogus = sum(1 for n in names if not (n and TUNNEL_NAME.match(n)))

    lines = [
        "  --- dns content check ---",
        f"  queries observed / expected = {len(names)} / {expected}",
        f"  responses                   = {responses}",
        f"  names that are not payloads = {bogus}",
        f"  distinct names / queries    = {len(set(names))} / {len(names)}",
    ]
    problems = []
    if expected and abs(len(names) - expected) > 0.05 * expected:
        problems.append(f"query count {len(names)} is not close to the expected {expected}")
    if bogus:
        problems.append(f"{bogus} query names are not tunnel payloads")
    if len(set(names)) != len(names):
        problems.append("duplicate query names")
    if names and responses < 0.9 * len(names):
        problems.append("fewer than 90 percent of queries were answered")
    lines.append("  content verdict             = " + ("OK" if not problems else "FAILED"))
    lines += [f"  *** {p}" for p in problems]
    return lines

def summarize(run_id: int):
    with connect() as conn:
        run = conn.execute(select(ObservationRun.__table__).where(
            ObservationRun.run_id == run_id
        )).mappings().first()
        if run is None:
            print(f"No run with run_id={run_id}")
            return

        correlated_total = conn.scalar(select(func.count()).select_from(CorrelatedEventModel).where(
            CorrelatedEventModel.run_id == run_id
        ))
        tcp_flows_raw_total = conn.scalar(select(func.count()).select_from(TcpFlowRaw).where(
            TcpFlowRaw.run_id == run_id
        ))
        dns_raw_total = conn.scalar(select(func.count()).select_from(DnsEventRaw).where(
            DnsEventRaw.run_id == run_id
        ))
        dns_query_total = conn.scalar(select(func.count()).select_from(DnsEventRaw).where(
            DnsEventRaw.run_id == run_id, DnsEventRaw.event_type == "dns_query"
        ))
        dns_response_total = conn.scalar(select(func.count()).select_from(DnsEventRaw).where(
            DnsEventRaw.run_id == run_id, DnsEventRaw.event_type == "dns_response"
        ))
        dns_nxdomain_total = conn.scalar(select(func.count()).select_from(DnsEventRaw).where(
            DnsEventRaw.run_id == run_id, DnsEventRaw.rcode == 3
        ))

        def rate(col):
            column = getattr(CorrelatedEventModel, col)
            result = conn.scalar(select(func.avg(case((column != 0, 1.0), else_=0.0))).where(
                CorrelatedEventModel.run_id == run_id
            ))
            return round(result, 3) if result is not None else None

        ssh = conn.scalar(select(func.count()).select_from(SshSession).where(
            SshSession.run_id == run_id
        ))

        meta = conn.execute(select(AttackRunMetadata.__table__).where(
            AttackRunMetadata.run_id == run_id
        )).mappings().first()

        lines = [
            f"run_id={run['run_id']}  scenario={run['scenario']}  label={run['label']}",
            f"  status             = {run['status']}",
            f"  quality            = {run.get('quality') or '(not set)'}",
            f"  failure_reason     = {run.get('failure_reason') or '-'}",
            f"  duration_ms        = {run['duration_ms']}",
            f"  notes              = {run['notes']}",
        ]

        lines.append("  --- correlated_events (per-connection, TCP-connect anchored) ---")
        lines.append(f"  tcp_connect_events = {correlated_total}")
        for col in ("tls_matched", "dns_matched", "process_context_matched", "http_matched"):
            lines.append(f"  {col:26s} = {rate(col)}")

        lines.append("  --- raw signal tables (independent of correlation) ---")
        lines.append(f"  tcp_flows_raw           = {tcp_flows_raw_total}")
        lines.append(f"  dns_events_raw          = {dns_raw_total} "
                     f"(queries={dns_query_total}, responses={dns_response_total}, nxdomain={dns_nxdomain_total})")
        lines.append(f"  ssh_sessions            = {ssh}")

        if correlated_total == 0 and (tcp_flows_raw_total or dns_raw_total):
            lines.append("  NOTE: 0 correlated_events is expected for UDP-only, inbound-only, "
                         "or local-only techniques (see docs/010, docs/011). Check the raw "
                         "tables above before assuming the run failed.")
        if correlated_total == 0 and not tcp_flows_raw_total and not dns_raw_total and not ssh:
            lines.append("  WARNING: no correlated events AND no raw signal of any kind. "
                         "This run likely produced no real telemetry; verify the scenario "
                         "actually reached its target before trusting this data.")

        if run["label"] and run["label"].startswith("attack:"):
            lines.append("  --- attack metadata ---")
            if meta is None:
                lines.append("  *** WARNING: attack run has NO attack_run_metadata row ***")
            else:
                lines.append(f"  attack_run_metadata     = present")
                lines.append(f"  run_uuid                = {meta.get('run_uuid')}")
                lines.append(f"  manifest_path           = {meta.get('manifest_path')}")
                lines.append(f"  manifest_hash           = {meta.get('manifest_hash')}")
                lines.append(f"  tool                    = {meta.get('tool')} {meta.get('tool_version') or ''}".rstrip())
                lines.append(f"  target                  = {meta.get('target_host')}:{meta.get('target_port')}")
                lines.append(f"  intensity               = {meta.get('intensity')}")
                lines.append(f"  attack_family/technique = {meta.get('attack_family')}/{meta.get('attack_technique')}")
                if meta.get("allow_nonzero_exit"):
                    lines.append(f"  allow_nonzero_exit      = True  <- run kept despite a failing repetition")
                if meta is not None and run["scenario"] == "dns_tunneling":
                    lines.extend(dns_content_check(conn, run_id, meta))

        summary = "\n".join(lines)
        print(summary)
        with SUMMARY_FILE.open("a", encoding="utf-8") as f:
            f.write(summary + "\n" + "=" * 60 + "\n\n")
        print(f"\nSummary appended to: {SUMMARY_FILE}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 -m observation.database.reports.run_summary <run_id>")
        sys.exit(1)
    summarize(int(sys.argv[1]))