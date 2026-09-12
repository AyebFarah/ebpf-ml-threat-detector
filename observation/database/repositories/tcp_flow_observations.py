from __future__ import annotations
import json
from sqlalchemy.orm import Session
from sqlalchemy import select
from observation.database.models import TcpFlowObservation


class TcpFlowObservationsRepository:
    def __init__(self, conn: Session):
        self.conn = conn

    def insert(self, correlated_event_id: int, tcp_block: dict) -> None:
        if not tcp_block:
            return
        self.conn.add(TcpFlowObservation(
            correlated_event_id=correlated_event_id, start_ts=tcp_block.get("start_ts"),
            end_ts=tcp_block.get("end_ts"), duration_ms=tcp_block.get("duration_ms"),
            handshake_completed=int(bool(tcp_block.get("handshake_completed"))),
            handshake_rtt_ms=tcp_block.get("handshake_rtt_ms"),
            termination_reason=tcp_block.get("termination_reason"),
            packets_out=tcp_block.get("packets_out"), packets_in=tcp_block.get("packets_in"),
            bytes_out=tcp_block.get("bytes_out"), bytes_in=tcp_block.get("bytes_in"),
            retransmissions=tcp_block.get("retransmissions"), raw_json=json.dumps(tcp_block),
        ))

    def for_correlated_event(self, correlated_event_id: int) -> list:
        return list(self.conn.execute(select(TcpFlowObservation.__table__).where(
            TcpFlowObservation.correlated_event_id == correlated_event_id
        )).mappings())
