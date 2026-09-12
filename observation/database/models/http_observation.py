from typing import Optional
from sqlalchemy import ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from observation.database.models.base import Base


class HttpObservation(Base):
    __tablename__ = "http_observations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    correlated_event_id: Mapped[int] = mapped_column(ForeignKey("correlated_events.id", ondelete="CASCADE"))
    request_timestamp: Mapped[Optional[str]] = mapped_column(Text)
    response_timestamp: Mapped[Optional[str]] = mapped_column(Text)
    method: Mapped[Optional[str]] = mapped_column(Text)
    host: Mapped[Optional[str]] = mapped_column(Text)
    path_hash: Mapped[Optional[str]] = mapped_column(Text)
    path_length: Mapped[Optional[int]] = mapped_column(Integer)
    user_agent_hash: Mapped[Optional[str]] = mapped_column(Text)
    status_code: Mapped[Optional[int]] = mapped_column(Integer)
    content_type: Mapped[Optional[str]] = mapped_column(Text)
    content_length: Mapped[Optional[int]] = mapped_column(Integer)
    raw_json: Mapped[Optional[str]] = mapped_column(Text)
    correlated_event: Mapped["CorrelatedEventModel"] = relationship(back_populates="http_observations")
