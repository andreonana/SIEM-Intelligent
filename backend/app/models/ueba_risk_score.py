# backend/app/models/ueba_risk_score.py
#
# Modèle SQLAlchemy pour les scores de risque UEBA.
# Un enregistrement par entité et par analyse — les plus récents remplacent les anciens.

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class UEBARiskScore(Base):
    __tablename__ = "ueba_risk_scores"

    id:                 Mapped[int]        = mapped_column(primary_key=True, autoincrement=True)
    entity_type:        Mapped[str]        = mapped_column(String(32),  nullable=False, index=True)
    entity_id:          Mapped[str]        = mapped_column(String(256), nullable=False, index=True)
    score:              Mapped[float]      = mapped_column(Float,       nullable=False)
    risk_level:         Mapped[str]        = mapped_column(String(16),  nullable=False)
    anomaly_count:      Mapped[int]        = mapped_column(Integer,     nullable=False, default=0)
    contributing_types: Mapped[str | None] = mapped_column(Text,       nullable=True)
    justification:      Mapped[str | None] = mapped_column(Text,       nullable=True)
    computed_at:        Mapped[datetime]   = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    def to_dict(self) -> dict:
        return {
            "id":                 self.id,
            "entity_type":        self.entity_type,
            "entity_id":          self.entity_id,
            "score":              self.score,
            "risk_level":         self.risk_level,
            "anomaly_count":      self.anomaly_count,
            "contributing_types": self.contributing_types,
            "justification":      self.justification,
            "computed_at":        self.computed_at.isoformat() if self.computed_at else None,
        }
