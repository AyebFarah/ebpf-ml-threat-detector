"""Usage: python3 -m observation.database.reports.run_summary <run_id>"""

import sqlite3
import sys
from pathlib import Path

from observation import paths


SUMMARY_FILE = Path(__file__).parent / "run_summary.txt"


def summarize(run_id: int):
    conn = sqlite3.connect(paths.DATABASE_FILE)
    conn.row_factory = sqlite3.Row

    try:
        run = conn.execute(
            "SELECT * FROM observation_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()

        if run is None:
            message = f"No run with run_id={run_id}"
            print(message)
            return

        total = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM correlated_events
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()["c"]

        def rate(col):
            result = conn.execute(
                f"""
                SELECT AVG(
                    CASE WHEN {col} THEN 1.0 ELSE 0 END
                ) AS r
                FROM correlated_events
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()["r"]

            return round(result, 3) if result is not None else None

        ssh = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM ssh_sessions
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()["c"]

        lines = [
            f"run_id={run['run_id']}  "
            f"scenario={run['scenario']}  "
            f"label={run['label']}",
            f"  status             = {run['status']}",
            f"  duration_seconds   = {run['duration_seconds']}",
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

    finally:
        conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: python3 -m "
            "observation.database.reports.run_summary <run_id>"
        )
        sys.exit(1)

    summarize(int(sys.argv[1]))