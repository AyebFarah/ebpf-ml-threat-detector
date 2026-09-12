from sqlalchemy import Text, text
from sqlalchemy.orm import Mapped, mapped_column
from observation.database.models.base import Base


class SchemaMigration(Base):
    __tablename__ = "schema_migrations"
    version: Mapped[str] = mapped_column(Text, primary_key=True)
    applied_at: Mapped[str] = mapped_column(Text, server_default=text("(datetime('now'))"))
