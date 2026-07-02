# backend/app/models/ueba_anomaly.py
#
# Modèle SQLAlchemy pour les anomalies comportementales détectées par le module UEBA.
# Persistées en SQL pour être requêtables sans recalcul ES.

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class UEBAAnomaly(Base):
    __tablename__ = "ueba_anomalies"

    id:           Mapped[int]        = mapped_column(primary_key=True, autoincrement=True)
    entity_type:  Mapped[str]        = mapped_column(String(32),  nullable=False, index=True)
    entity_id:    Mapped[str]        = mapped_column(String(256), nullable=False, index=True)
    anomaly_type: Mapped[str]        = mapped_column(String(64),  nullable=False)
    severity:     Mapped[str]        = mapped_column(String(16),  nullable=False)
    weight:       Mapped[float]      = mapped_column(Float,       nullable=False, default=0.0)
    description:  Mapped[str]        = mapped_column(Text,        nullable=False)
    evidence:     Mapped[str | None] = mapped_column(Text,        nullable=True)
    detected_at:  Mapped[datetime]   = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    # Lien optionnel vers une alerte de corrélation
    alert_id:     Mapped[int | None] = mapped_column(nullable=True)
    # Indique si cette anomalie a déclenché une alerte
    alerted:      Mapped[bool]       = mapped_column(default=False, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id":           self.id,
            "entity_type":  self.entity_type,
            "entity_id":    self.entity_id,
            "anomaly_type": self.anomaly_type,
            "severity":     self.severity,
            "weight":       self.weight,
            "description":  self.description,
            "evidence":     self.evidence,
            "detected_at":  self.detected_at.isoformat() if self.detected_at else None,
            "alert_id":     self.alert_id,
            "alerted":      self.alerted,
        }
