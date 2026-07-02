# backend/app/models/playbook_execution.py
#
# Modèle SQLAlchemy représentant l'exécution d'un playbook SOAR.
# V3 : ajout soar_mode, scheduled_at pour le mode CONFIRM.

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id:           Mapped[int]          = mapped_column(primary_key=True, autoincrement=True)
    playbook_id:  Mapped[str]          = mapped_column(String(64), nullable=False)
    alert_id:     Mapped[int | None]   = mapped_column(Integer, nullable=True)
    triggered_by: Mapped[str]          = mapped_column(String(64), nullable=False)
    params:       Mapped[str | None]   = mapped_column(Text, nullable=True)   # JSON
    result:       Mapped[str | None]   = mapped_column(Text, nullable=True)   # JSON
    status:       Mapped[str]          = mapped_column(String(32), nullable=False)  # success|failure|partial|scheduled|cancelled
    executed_at:  Mapped[datetime]     = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # V3 — Mode d'exécution : AUTO | CONFIRM | MANUAL
    soar_mode:    Mapped[str]          = mapped_column(String(16), default="MANUAL", nullable=False)

    # V3 — Date planifiée pour le mode CONFIRM (None si AUTO ou MANUAL).
    scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id":           self.id,
            "playbook_id":  self.playbook_id,
            "alert_id":     self.alert_id,
            "triggered_by": self.triggered_by,
            "params":       self.params,
            "result":       self.result,
            "status":       self.status,
            "executed_at":  self.executed_at.isoformat() if self.executed_at else None,
            "soar_mode":    self.soar_mode,
            "scheduled_at": self.scheduled_at.isoformat() if self.scheduled_at else None,
        }
