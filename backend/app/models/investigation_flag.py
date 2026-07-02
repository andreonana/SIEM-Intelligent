# backend/app/models/investigation_flag.py
#
# Marquage persistant d'une entité (IP, host, utilisateur) comme suspecte,
# pour investigation croisée entre analystes.

from datetime import datetime, timezone

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class InvestigationFlag(Base):
    __tablename__ = "investigation_flags"

    id:          Mapped[int]      = mapped_column(primary_key=True, autoincrement=True)
    entity_id:   Mapped[str]      = mapped_column(String(256), nullable=False, index=True)
    flagged_by:  Mapped[str]      = mapped_column(String(64), nullable=False)
    note:        Mapped[str | None] = mapped_column(Text, nullable=True)
    flagged_at:  Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "entity_id": self.entity_id,
            "flagged_by": self.flagged_by,
            "note": self.note,
            "flagged_at": self.flagged_at.isoformat() if self.flagged_at else None,
        }
