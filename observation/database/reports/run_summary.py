"""Usage: python3 -m observation.database.reports.run_summary <run_id>"""

import sys
from sqlalchemy import case, func, select

from observation import paths
from observation.database.connection import connect
from observation.database.models import AttackRunMetadata, CorrelatedEventModel, ObservationRun, SshSession


SUMMARY_FILE = paths.RUN_SUMMARY_FILE


def summarize(run_id: int):
    with connect() as conn:
        run = conn.execute(select(ObservationRun.__table__).where(
            ObservationRun.run_id == run_id
        )).mappings().first()

        if run is None:
            message = f"No run with run_id={run_id}"
            print(message)
            return

        total = conn.scalar(select(func.count()).select_from(CorrelatedEventModel).where(
            CorrelatedEventModel.run_id == run_id
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

        lines = [
            f"run_id={run['run_id']}  "
            f"scenario={run['scenario']}  "
            f"label={run['label']}",
            f"  status             = {run['status']}",
            f"  duration_ms        = {run['duration_ms']}",
            f"  notes              = {run['notes']}",
            f"  tcp_connect_events = {total}",
        ]

        for col in (
                "tls_matched",
                "dns_matched",
                "process_context_matched",
                "http_matched",
        ):
            lines.append(
                f"  {col:26s} = {rate(col)}"
            )

        lines.append(f"  ssh_sessions       = {ssh}")

        # Attack-run audit check: every attack:* labeled run must have a
        # matching attack_run_metadata row (inserted automatically by the
        # attack wrapper). A missing row means the run bypassed the wrapper
        # (e.g. was created manually) and needs backfilling before it
        # counts as audit-complete. Kept in `lines` so it's captured in
        # both terminal output and the persisted summary file, not just
        # flashed to the terminal and lost.
        if run["label"] and run["label"].startswith("attack:"):
            meta = conn.scalar(select(AttackRunMetadata.run_id).where(
                AttackRunMetadata.run_id == run_id
            ))
            if meta is None:
                lines.append("  *** WARNING: attack run has NO attack_run_metadata row ***")
            else:
                lines.append("  attack_run_metadata      = present")

        summary = "\n".join(lines)

        # Print summary to terminal
        print(summary)

        # Append summary to the same file
        with SUMMARY_FILE.open("a", encoding="utf-8") as f:
            f.write(summary)
            f.write("\n")
            f.write("=" * 60)
            f.write("\n\n")

        print(f"\nSummary appended to: {SUMMARY_FILE}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: python3 -m "
            "observation.database.reports.run_summary <run_id>"
        )
        sys.exit(1)

    summarize(int(sys.argv[1]))
