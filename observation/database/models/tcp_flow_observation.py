from typing import Optional
from sqlalchemy import Float, ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from observation.database.models.base import Base


class TcpFlowObservation(Base):
    __tablename__ = "tcp_flow_observations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    correlated_event_id: Mapped[int] = mapped_column(ForeignKey("correlated_events.id", ondelete="CASCADE"))
    start_ts: Mapped[Optional[str]] = mapped_column(Text)
    end_ts: Mapped[Optional[str]] = mapped_column(Text)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer)
    handshake_completed: Mapped[Optional[int]] = mapped_column(Integer)
    handshake_rtt_ms: Mapped[Optional[float]] = mapped_column(Float)
    termination_reason: Mapped[Optional[str]] = mapped_column(Text)
    packets_out: Mapped[Optional[int]] = mapped_column(Integer)
    packets_in: Mapped[Optional[int]] = mapped_column(Integer)
    bytes_out: Mapped[Optional[int]] = mapped_column(Integer)
    bytes_in: Mapped[Optional[int]] = mapped_column(Integer)
    retransmissions: Mapped[Optional[int]] = mapped_column(Integer)
    raw_json: Mapped[Optional[str]] = mapped_column(Text)
    correlated_event: Mapped["CorrelatedEventModel"] = relationship(back_populates="tcp_flow_observations")
