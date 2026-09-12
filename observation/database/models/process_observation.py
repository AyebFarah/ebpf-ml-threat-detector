from typing import Optional
from sqlalchemy import ForeignKey, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from observation.database.models.base import Base


class ProcessObservation(Base):
    __tablename__ = "process_observations"
    __table_args__ = (
        Index("idx_process_observations_correlated_event_id", "correlated_event_id"),
        Index("idx_process_observations_exec_id", "exec_id"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    correlated_event_id: Mapped[int] = mapped_column(ForeignKey("correlated_events.id", ondelete="CASCADE"))
    timestamp: Mapped[Optional[str]] = mapped_column(Text)
    exec_id: Mapped[Optional[str]] = mapped_column(Text)
    parent_exec_id: Mapped[Optional[str]] = mapped_column(Text)
    parent_binary: Mapped[Optional[str]] = mapped_column(Text)
    arguments: Mapped[Optional[str]] = mapped_column(Text)
    uid: Mapped[Optional[int]] = mapped_column(Integer)
    cwd: Mapped[Optional[str]] = mapped_column(Text)
    raw_json: Mapped[Optional[str]] = mapped_column(Text)
    correlated_event: Mapped["CorrelatedEventModel"] = relationship(back_populates="process_observations")
