from typing import Optional

from sqlalchemy import Float, ForeignKey, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from observation.database.models.base import Base


class CorrelatedEventModel(Base):
    __tablename__ = "correlated_events"
    __table_args__ = (
        Index("idx_correlated_events_run_id", "run_id"),
        Index("idx_correlated_events_timestamp", "timestamp"),
        Index("idx_correlated_events_dst_ip", "dst_ip"),
        Index("idx_correlated_events_process_pid", "process_pid"),
        Index("idx_correlated_events_run_timestamp", "run_id", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("observation_runs.run_id", ondelete="CASCADE"))
    timestamp: Mapped[str] = mapped_column(Text)
    src_ip: Mapped[Optional[str]] = mapped_column(Text)
    dst_ip: Mapped[Optional[str]] = mapped_column(Text)
    src_port: Mapped[Optional[int]] = mapped_column(Integer)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer)
    transport: Mapped[Optional[str]] = mapped_column(Text)
    direction: Mapped[Optional[str]] = mapped_column(Text)
    process_pid: Mapped[Optional[int]] = mapped_column(Integer)
    process_name: Mapped[Optional[str]] = mapped_column(Text)
    dns_matched: Mapped[int] = mapped_column(Integer, default=0)
    dns_method: Mapped[Optional[str]] = mapped_column(Text)
    dns_time_delta_ms: Mapped[Optional[int]] = mapped_column(Integer)
    dns_response_latency_ms: Mapped[Optional[float]] = mapped_column(Float)
    tls_matched: Mapped[int] = mapped_column(Integer, default=0)
    tls_method: Mapped[Optional[str]] = mapped_column(Text)
    tls_time_delta_ms: Mapped[Optional[int]] = mapped_column(Integer)
    ssh_matched: Mapped[int] = mapped_column(Integer, default=0)
    ssh_method: Mapped[Optional[str]] = mapped_column(Text)
    ssh_time_delta_ms: Mapped[Optional[int]] = mapped_column(Integer)
    tcp_flow_matched: Mapped[int] = mapped_column(Integer, default=0)
    tcp_flow_method: Mapped[Optional[str]] = mapped_column(Text)
    tcp_flow_time_delta_ms: Mapped[Optional[int]] = mapped_column(Integer)
    http_matched: Mapped[int] = mapped_column(Integer, default=0)
    http_method: Mapped[Optional[str]] = mapped_column(Text)
    http_time_delta_ms: Mapped[Optional[int]] = mapped_column(Integer)
    process_context_matched: Mapped[int] = mapped_column(Integer, default=0)
    process_context_method: Mapped[Optional[str]] = mapped_column(Text)
    file_activity_count: Mapped[int] = mapped_column(Integer, default=0)
    file_activity_method: Mapped[Optional[str]] = mapped_column(Text)
    privilege_activity_count: Mapped[int] = mapped_column(Integer, default=0)
    privilege_activity_method: Mapped[Optional[str]] = mapped_column(Text)
    raw_json: Mapped[str] = mapped_column(Text)
    run: Mapped["ObservationRun"] = relationship(back_populates="correlated_events")
    process_observations: Mapped[list["ProcessObservation"]] = relationship(
        back_populates="correlated_event", cascade="all, delete-orphan"
    )
    dns_observations: Mapped[list["DnsObservation"]] = relationship(
        back_populates="correlated_event", cascade="all, delete-orphan"
    )
    tls_observations: Mapped[list["TlsObservation"]] = relationship(
        back_populates="correlated_event", cascade="all, delete-orphan"
    )
    tcp_flow_observations: Mapped[list["TcpFlowObservation"]] = relationship(
        back_populates="correlated_event", cascade="all, delete-orphan"
    )
    http_observations: Mapped[list["HttpObservation"]] = relationship(
        back_populates="correlated_event", cascade="all, delete-orphan"
    )
    file_activity_events: Mapped[list["FileActivityEvent"]] = relationship(
        back_populates="correlated_event", cascade="all, delete-orphan"
    )
    privilege_activity_events: Mapped[list["PrivilegeActivityEvent"]] = relationship(
        back_populates="correlated_event", cascade="all, delete-orphan"
    )
