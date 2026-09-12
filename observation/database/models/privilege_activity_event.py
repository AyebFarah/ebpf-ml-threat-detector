from typing import Optional
from sqlalchemy import ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from observation.database.models.base import Base


class PrivilegeActivityEvent(Base):
    __tablename__ = "privilege_activity_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    correlated_event_id: Mapped[int] = mapped_column(ForeignKey("correlated_events.id", ondelete="CASCADE"))
    timestamp: Mapped[Optional[str]] = mapped_column(Text)
    event_type: Mapped[Optional[str]] = mapped_column(Text)
    detail: Mapped[Optional[str]] = mapped_column(Text)
    source_event_key: Mapped[Optional[str]] = mapped_column(Text)
    correlated_event: Mapped["CorrelatedEventModel"] = relationship(back_populates="privilege_activity_events")
from __future__ import annotations
