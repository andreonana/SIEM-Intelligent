# backend/app/models/user.py
#
# Modèle SQLAlchemy représentant un utilisateur du SIEM.
# Champs organisationnels (team, service, subsidiary, environment) prévus par le CDC
# pour la ségrégation des accès par périmètre.

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class User(Base):
    __tablename__ = "users"

    id:               Mapped[int]  = mapped_column(primary_key=True, autoincrement=True)
    username:         Mapped[str]  = mapped_column(String(64), unique=True, nullable=False, index=True)
    hashed_password:  Mapped[str]  = mapped_column(String(256), nullable=False)
    role:             Mapped[str]  = mapped_column(String(32), nullable=False)  # reader | analyst | administrator
    is_active:        Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Périmètre organisationnel (CDC — ségrégation des accès)
    team:             Mapped[str | None] = mapped_column(String(64),  nullable=True)
    service:          Mapped[str | None] = mapped_column(String(64),  nullable=True)
    subsidiary:       Mapped[str | None] = mapped_column(String(64),  nullable=True)
    environment:      Mapped[str | None] = mapped_column(String(32),  nullable=True)  # prod | staging | dev

    # MFA TOTP (RFC 6238)
    mfa_enabled:      Mapped[bool]         = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret:       Mapped[str | None]   = mapped_column(Text, nullable=True)
    mfa_enabled_at:   Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at:       Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at:       Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "username":      self.username,
            "role":          self.role,
            "is_active":     self.is_active,
            "mfa_enabled":   self.mfa_enabled,
            "mfa_enabled_at": self.mfa_enabled_at.isoformat() if self.mfa_enabled_at else None,
            "team":          self.team,
            "service":       self.service,
            "subsidiary":    self.subsidiary,
            "environment":   self.environment,
            "created_at":    self.created_at.isoformat() if self.created_at else None,
            "updated_at":    self.updated_at.isoformat() if self.updated_at else None,
        }
