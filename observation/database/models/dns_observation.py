from typing import Optional
from sqlalchemy import Float, ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from observation.database.models.base import Base


class DnsObservation(Base):
    __tablename__ = "dns_observations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    correlated_event_id: Mapped[int] = mapped_column(ForeignKey("correlated_events.id", ondelete="CASCADE"))
    timestamp: Mapped[Optional[str]] = mapped_column(Text)
    query_name: Mapped[Optional[str]] = mapped_column(Text)
    query_type: Mapped[Optional[int]] = mapped_column(Integer)
    transaction_id: Mapped[Optional[int]] = mapped_column(Integer)
    rcode: Mapped[Optional[int]] = mapped_column(Integer)
    answer_count: Mapped[Optional[int]] = mapped_column(Integer)
    resolved_ip: Mapped[Optional[str]] = mapped_column(Text)
    ttl: Mapped[Optional[int]] = mapped_column(Integer)
    response_latency_ms: Mapped[Optional[float]] = mapped_column(Float)
    raw_json: Mapped[Optional[str]] = mapped_column(Text)
    correlated_event: Mapped["CorrelatedEventModel"] = relationship(back_populates="dns_observations")
