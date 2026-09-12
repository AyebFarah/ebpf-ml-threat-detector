from __future__ import annotations

from typing import Optional

from sqlalchemy import Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from observation.database.models.base import Base


class ObservationRun(Base):
    __tablename__ = "observation_runs"

    run_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    started_at: Mapped[str] = mapped_column(Text)
    ended_at: Mapped[Optional[str]] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, default="running")
    correlated_events_count: Mapped[int] = mapped_column(Integer, default=0)
    ssh_sessions_count: Mapped[int] = mapped_column(Integer, default=0)
    source_correlated_file: Mapped[Optional[str]] = mapped_column(Text)
    source_ssh_sessions_file: Mapped[Optional[str]] = mapped_column(Text)
    scenario: Mapped[Optional[str]] = mapped_column(Text)
    label: Mapped[Optional[str]] = mapped_column(Text, default="benign")
    notes: Mapped[Optional[str]] = mapped_column(Text)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer)
    correlated_events: Mapped[list["CorrelatedEventModel"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    ssh_sessions: Mapped[list["SshSession"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    tcp_flows_raw: Mapped[list["TcpFlowRaw"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    dns_events_raw: Mapped[list["DnsEventRaw"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    feature_windows: Mapped[list["FeatureWindow"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    attack_metadata: Mapped[Optional["AttackRunMetadata"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", uselist=False
    )
