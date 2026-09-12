from typing import Optional
from sqlalchemy import Float, ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from observation.database.models.base import Base


class SshSession(Base):
    __tablename__ = "ssh_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("observation_runs.run_id", ondelete="CASCADE"))
    session_key: Mapped[Optional[str]] = mapped_column(Text)
    username: Mapped[Optional[str]] = mapped_column(Text)
    src_ip: Mapped[Optional[str]] = mapped_column(Text)
    src_port: Mapped[Optional[int]] = mapped_column(Integer)
    pid: Mapped[Optional[int]] = mapped_column(Integer)
    earliest_event_ts: Mapped[Optional[str]] = mapped_column(Text)
    auth_success_ts: Mapped[Optional[str]] = mapped_column(Text)
    auth_method: Mapped[Optional[str]] = mapped_column(Text)
    session_opened_ts: Mapped[Optional[str]] = mapped_column(Text)
    session_closed_ts: Mapped[Optional[str]] = mapped_column(Text)
    session_duration_seconds: Mapped[Optional[float]] = mapped_column(Float)
    disconnected_ts: Mapped[Optional[str]] = mapped_column(Text)
    tcp_connect_matched: Mapped[int] = mapped_column(Integer, default=0)
    tcp_connect_dst_ip: Mapped[Optional[str]] = mapped_column(Text)
    tcp_connect_time_delta_ms: Mapped[Optional[int]] = mapped_column(Integer)
    tcp_close_matched: Mapped[int] = mapped_column(Integer, default=0)
    tcp_close_timestamp: Mapped[Optional[str]] = mapped_column(Text)
    connection_duration_seconds: Mapped[Optional[float]] = mapped_column(Float)
    execve_matched: Mapped[int] = mapped_column(Integer, default=0)
    execve_binary: Mapped[Optional[str]] = mapped_column(Text)
    execve_timestamp: Mapped[Optional[str]] = mapped_column(Text)
    raw_json: Mapped[str] = mapped_column(Text)
    run: Mapped["ObservationRun"] = relationship(back_populates="ssh_sessions")
