# backend/app/models/audit_log.py
#
# Journalisation des actions utilisateurs exigée par le CDC :
# login, logout, create_user, role_update, alert_view, alert_acknowledge.
# Stockée en base SQL pour garantir la traçabilité même si ES est indisponible.

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id:          Mapped[int]       = mapped_column(primary_key=True, autoincrement=True)
    timestamp:   Mapped[datetime]  = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    username:    Mapped[str]       = mapped_column(String(64), nullable=False, index=True)
    role:        Mapped[str | None] = mapped_column(String(32), nullable=True)
    action:      Mapped[str]       = mapped_column(String(64), nullable=False)
    # Actions définies : login | logout | create_user | role_update | alert_view | alert_acknowledge
    target:      Mapped[str | None] = mapped_column(String(256), nullable=True)
    detail:      Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address:  Mapped[str | None] = mapped_column(String(64), nullable=True)
    result:      Mapped[str]        = mapped_column(String(16), default="success", nullable=False)
    # result : success | failure
