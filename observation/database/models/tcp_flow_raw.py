from typing import Optional
from sqlalchemy import Float, ForeignKey, Integer, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from observation.database.models.base import Base


class TcpFlowRaw(Base):
    __tablename__ = "tcp_flows_raw"
    __table_args__ = (UniqueConstraint("run_id", "dedup_key", name="uq_tcp_flows_raw_run_dedup"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("observation_runs.run_id", ondelete="CASCADE"))
    dedup_key: Mapped[str] = mapped_column(Text)
    src_ip: Mapped[Optional[str]] = mapped_column(Text)
    src_port: Mapped[Optional[int]] = mapped_column(Integer)
    dst_ip: Mapped[Optional[str]] = mapped_column(Text)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer)
    transport: Mapped[Optional[str]] = mapped_column(Text)
    direction: Mapped[Optional[str]] = mapped_column(Text)
    start_ts: Mapped[Optional[str]] = mapped_column(Text)
    end_ts: Mapped[Optional[str]] = mapped_column(Text)
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
    run: Mapped["ObservationRun"] = relationship(back_populates="tcp_flows_raw")
