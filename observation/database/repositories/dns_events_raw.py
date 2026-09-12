from __future__ import annotations
import json
import sqlite3
from observation.pipeline.event_keys import make_dns_dedup_key

class DnsEventsRawRepository:
    def __init__(self, conn: Session):
        self.conn = conn

    def insert_many(self, run_id: int, records: list) -> int:
        count = 0
        for r in records:
            if r.get("event_type") not in ("dns_query", "dns_response"):
                continue
            dedup_key = make_dns_dedup_key(r)
            result = self.conn.execute(insert(DnsEventRaw).values(
                run_id=run_id, dedup_key=dedup_key, timestamp=r.get("timestamp"),
                event_type=r.get("event_type"), src_ip=r.get("src_ip"), dst_ip=r.get("dst_ip"),
                src_port=r.get("src_port"), dst_port=r.get("dst_port"),
                transport=r.get("transport"), direction=r.get("direction"),
                query_name=r.get("query_name"), query_type=r.get("query_type"),
                transaction_id=r.get("transaction_id"), rcode=r.get("rcode"),
                answer_count=r.get("answer_count"), resolved_ip=r.get("resolved_ip"),
                ttl=(r.get("answers") or [{}])[0].get("ttl") if r.get("answers") else None,
                raw_json=json.dumps(r),
            ).on_conflict_do_nothing(index_elements=["run_id", "dedup_key"]))
            if result.rowcount:
                count += 1
        return count

    def for_run(self, run_id: int) -> list:
        return self.conn.execute(
            "SELECT * FROM dns_events_raw WHERE run_id = ? ORDER BY timestamp", (run_id,)
        ).fetchall()
