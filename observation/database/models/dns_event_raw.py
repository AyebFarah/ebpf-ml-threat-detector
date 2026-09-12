from typing import Optional
from sqlalchemy import ForeignKey, Index, Integer, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from observation.database.models.base import Base


class DnsEventRaw(Base):
    __tablename__ = "dns_events_raw"
    __table_args__ = (
        UniqueConstraint("run_id", "dedup_key", name="uq_dns_events_raw_run_dedup"),
        Index("idx_dns_events_raw_run_id", "run_id"),
        Index("idx_dns_events_raw_query_name", "query_name"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("observation_runs.run_id", ondelete="CASCADE"))
    dedup_key: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[Optional[str]] = mapped_column(Text)
    event_type: Mapped[Optional[str]] = mapped_column(Text)
    src_ip: Mapped[Optional[str]] = mapped_column(Text)
    dst_ip: Mapped[Optional[str]] = mapped_column(Text)
    src_port: Mapped[Optional[int]] = mapped_column(Integer)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer)
    transport: Mapped[Optional[str]] = mapped_column(Text)
    direction: Mapped[Optional[str]] = mapped_column(Text)
    query_name: Mapped[Optional[str]] = mapped_column(Text)
    query_type: Mapped[Optional[int]] = mapped_column(Integer)
    transaction_id: Mapped[Optional[int]] = mapped_column(Integer)
    rcode: Mapped[Optional[int]] = mapped_column(Integer)
    answer_count: Mapped[Optional[int]] = mapped_column(Integer)
    resolved_ip: Mapped[Optional[str]] = mapped_column(Text)
    ttl: Mapped[Optional[int]] = mapped_column(Integer)
    raw_json: Mapped[Optional[str]] = mapped_column(Text)
    run: Mapped["ObservationRun"] = relationship(back_populates="dns_events_raw")
