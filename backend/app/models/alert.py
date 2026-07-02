# backend/app/models/alert.py
#
# Modèle SQLAlchemy représentant une alerte de sécurité générée par le moteur de corrélation.
# V3 : ajout confidence_score, soar_status.

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id:               Mapped[int]             = mapped_column(primary_key=True, autoincrement=True)
    rule_id:          Mapped[str]             = mapped_column(String(64), nullable=False)
    rule_name:        Mapped[str]             = mapped_column(String(256), nullable=False)
    severity:         Mapped[str]             = mapped_column(String(16), nullable=False)
    description:      Mapped[str]             = mapped_column(Text, nullable=False)
    status:           Mapped[str]             = mapped_column(String(32), default="open", nullable=False)
    source_ip:        Mapped[str | None]      = mapped_column(String(64), nullable=True)
    host:             Mapped[str | None]      = mapped_column(String(256), nullable=True)
    related_log_ids:  Mapped[str | None]      = mapped_column(Text, nullable=True)
    detected_at:      Mapped[datetime]        = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    mitre_tactic:     Mapped[str | None]      = mapped_column(String(128), nullable=True)
    mitre_technique:  Mapped[str | None]      = mapped_column(String(64), nullable=True)
    assigned_to:      Mapped[str | None]      = mapped_column(String(64), nullable=True)
    acknowledged_by:  Mapped[str | None]      = mapped_column(String(64), nullable=True)
    acknowledged_at:  Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_note:  Mapped[str | None]      = mapped_column(Text, nullable=True)
    resolved_at:      Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dedupe_key:       Mapped[str | None]      = mapped_column(String(256), nullable=True, index=True)

    # V3 — Confidence score hérité de la règle déclencheuse (0-100).
    # Permet de prioriser les alertes et d'ajuster l'escalade.
    confidence_score: Mapped[float]           = mapped_column(Float, default=80.0, nullable=False)

    # V3 — Statut SOAR : pending | scheduled | executed | cancelled | manual.
    soar_status:      Mapped[str]             = mapped_column(String(32), default="manual", nullable=False)

    def to_dict(self) -> dict:
        return {
            "id":               self.id,
            "rule_id":          self.rule_id,
            "rule_name":        self.rule_name,
            "severity":         self.severity,
            "description":      self.description,
            "status":           self.status,
            "source_ip":        self.source_ip,
            "host":             self.host,
            "related_log_ids":  self.related_log_ids,
            "detected_at":      self.detected_at.isoformat() if self.detected_at else None,
            "mitre_tactic":     self.mitre_tactic,
            "mitre_technique":  self.mitre_technique,
            "assigned_to":      self.assigned_to,
            "acknowledged_by":  self.acknowledged_by,
            "acknowledged_at":  self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolution_note":  self.resolution_note,
            "resolved_at":      self.resolved_at.isoformat() if self.resolved_at else None,
            "dedupe_key":       self.dedupe_key,
            "confidence_score": self.confidence_score,
            "soar_status":      self.soar_status,
        }
