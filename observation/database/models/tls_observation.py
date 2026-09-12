from typing import Optional
from sqlalchemy import ForeignKey, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from observation.database.models.base import Base


class TlsObservation(Base):
    __tablename__ = "tls_observations"
    __table_args__ = (
        Index("idx_tls_observations_correlated_event_id", "correlated_event_id"),
        Index("idx_tls_observations_sni", "sni"),
        Index("idx_tls_observations_ja4", "ja4"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    correlated_event_id: Mapped[int] = mapped_column(ForeignKey("correlated_events.id", ondelete="CASCADE"))
    timestamp: Mapped[Optional[str]] = mapped_column(Text)
    sni: Mapped[Optional[str]] = mapped_column(Text)
    ja4: Mapped[Optional[str]] = mapped_column(Text)
    tls_version: Mapped[Optional[str]] = mapped_column(Text)
    raw_json: Mapped[Optional[str]] = mapped_column(Text)
    correlated_event: Mapped["CorrelatedEventModel"] = relationship(back_populates="tls_observations")
