from __future__ import annotations
import json
import sqlite3


class TcpFlowObservationsRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def insert(self, correlated_event_id: int, tcp_block: dict) -> None:
        if not tcp_block:
            return
        self.conn.execute(
            """
            INSERT INTO tcp_flow_observations (
                correlated_event_id, start_ts, end_ts, duration_seconds,
                handshake_completed, handshake_rtt_ms, termination_reason,
                packets_out, packets_in, bytes_out, bytes_in,
                retransmissions, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                correlated_event_id,
                tcp_block.get("start_ts"),
                tcp_block.get("end_ts"),
                tcp_block.get("duration_seconds"),
                int(bool(tcp_block.get("handshake_completed"))),
                tcp_block.get("handshake_rtt_ms"),
                tcp_block.get("termination_reason"),
                tcp_block.get("packets_out"),
                tcp_block.get("packets_in"),
                tcp_block.get("bytes_out"),
                tcp_block.get("bytes_in"),
                tcp_block.get("retransmissions"),
                json.dumps(tcp_block),
            ),
        )

    def for_correlated_event(self, correlated_event_id: int) -> list:
        return self.conn.execute(
            "SELECT * FROM tcp_flow_observations WHERE correlated_event_id = ?",
            (correlated_event_id,),
        ).fetchall()