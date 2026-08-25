from __future__ import annotations
import json
import sqlite3


class DnsObservationsRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def insert(self, correlated_event_id: int, dns_block: dict) -> None:
        if not dns_block:
            return
        self.conn.execute(
            """
            INSERT INTO dns_observations (
                correlated_event_id, timestamp, query_name, query_type,
                transaction_id, rcode, answer_count, resolved_ip, ttl,
                response_latency_ms, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                correlated_event_id,
                dns_block.get("timestamp"),
                dns_block.get("query_name"),
                dns_block.get("query_type"),
                dns_block.get("transaction_id"),
                dns_block.get("rcode"),
                dns_block.get("answer_count"),
                dns_block.get("resolved_ip"),
                (dns_block.get("answers") or [{}])[0].get("ttl") if dns_block.get("answers") else None,
                dns_block.get("response_latency_ms"),
                json.dumps(dns_block),
            ),
        )

    def for_correlated_event(self, correlated_event_id: int) -> list:
        return self.conn.execute(
            "SELECT * FROM dns_observations WHERE correlated_event_id = ?",
            (correlated_event_id,),
        ).fetchall()

    def for_query_name(self, query_name: str, run_id: int = None) -> list:
        if run_id is None:
            return self.conn.execute(
                "SELECT * FROM dns_observations WHERE query_name = ?", (query_name,)
            ).fetchall()
        return self.conn.execute(
            "SELECT d.* FROM dns_observations d "
            "JOIN correlated_events ce ON ce.id = d.correlated_event_id "
            "WHERE d.query_name = ? AND ce.run_id = ?",
            (query_name, run_id),
        ).fetchall()