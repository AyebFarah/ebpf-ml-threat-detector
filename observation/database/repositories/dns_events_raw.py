from __future__ import annotations
import json
import sqlite3
from ..pipeline.event_keys import make_dns_dedup_key


class DnsEventsRawRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def insert_many(self, run_id: int, records: list) -> int:
        count = 0
        for r in records:
            if r.get("event_type") not in ("dns_query", "dns_response"):
                continue
            dedup_key = make_dns_dedup_key(r)
            try:
                self.conn.execute(
                    """INSERT INTO dns_events_raw
                       (run_id, dedup_key, timestamp, event_type, src_ip, dst_ip,
                        src_port, dst_port, transport, direction, query_name,
                        query_type, transaction_id, rcode, answer_count,
                        resolved_ip, ttl, raw_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        run_id, dedup_key, r.get("timestamp"), r.get("event_type"),
                        r.get("src_ip"), r.get("dst_ip"), r.get("src_port"), r.get("dst_port"),
                        r.get("transport"), r.get("direction"), r.get("query_name"),
                        r.get("query_type"), r.get("transaction_id"), r.get("rcode"),
                        r.get("answer_count"), r.get("resolved_ip"),
                        (r.get("answers") or [{}])[0].get("ttl") if r.get("answers") else None,
                        json.dumps(r),
                    ),
                )
                count += 1
            except sqlite3.IntegrityError:
                continue
        return count

    def for_run(self, run_id: int) -> list:
        return self.conn.execute(
            "SELECT * FROM dns_events_raw WHERE run_id = ? ORDER BY timestamp", (run_id,)
        ).fetchall()