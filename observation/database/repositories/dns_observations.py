from __future__ import annotations
import json
from sqlalchemy.orm import Session
from sqlalchemy import select

from observation.database.models import CorrelatedEventModel, DnsObservation


class DnsObservationsRepository:
    def __init__(self, conn: Session):
        self.conn = conn

    def insert(self, correlated_event_id: int, dns_block: dict) -> None:
        if not dns_block:
            return
        self.conn.add(DnsObservation(
            correlated_event_id=correlated_event_id, timestamp=dns_block.get("timestamp"),
            query_name=dns_block.get("query_name"), query_type=dns_block.get("query_type"),
            transaction_id=dns_block.get("transaction_id"), rcode=dns_block.get("rcode"),
            answer_count=dns_block.get("answer_count"), resolved_ip=dns_block.get("resolved_ip"),
            ttl=(dns_block.get("answers") or [{}])[0].get("ttl") if dns_block.get("answers") else None,
            response_latency_ms=dns_block.get("response_latency_ms"), raw_json=json.dumps(dns_block),
        ))

    def for_correlated_event(self, correlated_event_id: int) -> list:
        return list(self.conn.execute(select(DnsObservation.__table__).where(
            DnsObservation.correlated_event_id == correlated_event_id
        )).mappings())

    def for_query_name(self, query_name: str, run_id: int = None) -> list:
        if run_id is None:
            statement = select(DnsObservation.__table__).where(DnsObservation.query_name == query_name)
        else:
            statement = select(DnsObservation.__table__).join(
                CorrelatedEventModel, CorrelatedEventModel.id == DnsObservation.correlated_event_id
            ).where(DnsObservation.query_name == query_name, CorrelatedEventModel.run_id == run_id)
        return list(self.conn.execute(statement).mappings())
