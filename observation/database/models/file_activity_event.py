from typing import Optional
from sqlalchemy import ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from observation.database.models.base import Base


class FileActivityEvent(Base):
    __tablename__ = "file_activity_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    correlated_event_id: Mapped[int] = mapped_column(ForeignKey("correlated_events.id", ondelete="CASCADE"))
    timestamp: Mapped[Optional[str]] = mapped_column(Text)
    path: Mapped[Optional[str]] = mapped_column(Text)
    operations: Mapped[Optional[str]] = mapped_column(Text)
    source_event_key: Mapped[Optional[str]] = mapped_column(Text)
    correlated_event: Mapped["CorrelatedEventModel"] = relationship(back_populates="file_activity_events")
