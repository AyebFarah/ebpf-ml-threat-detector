from typing import Optional
from sqlalchemy import ForeignKey, Integer, Text, text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from observation.database.models.base import Base


class AttackRunMetadata(Base):
    __tablename__ = "attack_run_metadata"
    run_id: Mapped[int] = mapped_column(ForeignKey("observation_runs.run_id", ondelete="CASCADE"), primary_key=True)
    attack_family: Mapped[str] = mapped_column(Text)
    attack_technique: Mapped[str] = mapped_column(Text)
    scenario: Mapped[str] = mapped_column(Text)
    tool: Mapped[Optional[str]] = mapped_column(Text)
    tool_version: Mapped[Optional[str]] = mapped_column(Text)
    target_host: Mapped[Optional[str]] = mapped_column(Text)
    target_port: Mapped[Optional[int]] = mapped_column(Integer)
    intensity: Mapped[Optional[str]] = mapped_column(Text)
    parameters: Mapped[Optional[str]] = mapped_column(Text)
    attack_start_ts: Mapped[Optional[str]] = mapped_column(Text)
    attack_end_ts: Mapped[Optional[str]] = mapped_column(Text)
    expected_behavior: Mapped[Optional[str]] = mapped_column(Text)
    tool_version_check: Mapped[Optional[str]] = mapped_column(Text)
    notes: Mapped[Optional[str]] = mapped_column(Text)
    operator: Mapped[Optional[str]] = mapped_column(Text)
    manifest_path: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(Text, server_default=text("(datetime('now'))"))
    run: Mapped["ObservationRun"] = relationship(back_populates="attack_metadata")
