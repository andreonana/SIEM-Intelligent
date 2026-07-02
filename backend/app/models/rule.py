# backend/app/models/rule.py
#
# Modèle SQLAlchemy représentant une règle de corrélation.
# V3 : ajout confidence_score, soar_mode, confirm_delay_seconds.

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class CorrelationRule(Base):
    __tablename__ = "correlation_rules"

    id:                    Mapped[int]          = mapped_column(primary_key=True, autoincrement=True)
    rule_id:               Mapped[str]          = mapped_column(String(64), unique=True, nullable=False)
    name:                  Mapped[str]          = mapped_column(String(256), nullable=False)
    description:           Mapped[str]          = mapped_column(Text, nullable=False, default="")
    rule_type:             Mapped[str]          = mapped_column(String(32), nullable=False)   # threshold | pattern
    enabled:               Mapped[bool]         = mapped_column(Boolean, default=True, nullable=False)
    threshold:             Mapped[int | None]   = mapped_column(Integer, nullable=True)
    window_minutes:        Mapped[int]          = mapped_column(Integer, default=10, nullable=False)
    severity:              Mapped[str]          = mapped_column(String(16), nullable=False)
    mitre_tactic:          Mapped[str | None]   = mapped_column(String(128), nullable=True)
    mitre_technique:       Mapped[str | None]   = mapped_column(String(64), nullable=True)
    soar_action:           Mapped[str | None]   = mapped_column(String(64), nullable=True)

    # V3 — Confidence score (0-100) : niveau de confiance dans les détections de cette règle.
    # Utilisé pour pondérer l'urgence, filtrer les faux positifs et prioriser l'escalade.
    confidence_score:      Mapped[float]        = mapped_column(Float, default=80.0, nullable=False)

    # V3 — Mode SOAR : AUTO (immédiat), CONFIRM (délai confirm_delay_seconds), MANUAL (humain).
    soar_mode:             Mapped[str]          = mapped_column(String(16), default="MANUAL", nullable=False)

    # V3 — Délai avant exécution en mode CONFIRM (secondes, défaut 60).
    confirm_delay_seconds: Mapped[int]          = mapped_column(Integer, default=60, nullable=False)

    created_at:            Mapped[datetime]     = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at:            Mapped[datetime]     = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def to_dict(self) -> dict:
        return {
            "id":                    self.id,
            "rule_id":               self.rule_id,
            "name":                  self.name,
            "description":           self.description,
            "rule_type":             self.rule_type,
            "enabled":               self.enabled,
            "threshold":             self.threshold,
            "window_minutes":        self.window_minutes,
            "severity":              self.severity,
            "mitre_tactic":          self.mitre_tactic,
            "mitre_technique":       self.mitre_technique,
            "soar_action":           self.soar_action,
            "confidence_score":      self.confidence_score,
            "soar_mode":             self.soar_mode,
            "confirm_delay_seconds": self.confirm_delay_seconds,
            "created_at":            self.created_at.isoformat() if self.created_at else None,
            "updated_at":            self.updated_at.isoformat() if self.updated_at else None,
        }
