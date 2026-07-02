# backend/app/models/log_batch.py
#
# Modèle SQLAlchemy pour la chaîne de custody des batches de logs.
# Chaque batch d'ingestion génère un enregistrement avec son hash SHA-256
# et une référence au hash du batch précédent (chaîne).

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class LogBatch(Base):
    __tablename__ = "log_batches"

    id:           Mapped[int]          = mapped_column(primary_key=True, autoincrement=True)

    # Identifiant unique du batch (UUID).
    batch_id:     Mapped[str]          = mapped_column(String(64), unique=True, nullable=False, index=True)

    # Hash SHA-256 du contenu du batch (logs sérialisés JSON canonique).
    sha256:       Mapped[str]          = mapped_column(String(64), nullable=False)

    # Hash SHA-256 du batch précédent pour former une chaîne vérifiable.
    # "0" * 64 si c'est le premier batch.
    parent_sha256: Mapped[str]         = mapped_column(String(64), nullable=False)

    # Nombre de logs dans ce batch.
    log_count:    Mapped[int]          = mapped_column(Integer, nullable=False)

    # Source : "ingestion_api" | "syslog" | "filebeat" | etc.
    source:       Mapped[str | None]   = mapped_column(String(64), nullable=True)

    # Payload haché (stockage optionnel du JSON tronqué pour audit — max 4096 chars).
    payload_preview: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at:   Mapped[datetime]     = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    def to_dict(self) -> dict:
        return {
            "id":              self.id,
            "batch_id":        self.batch_id,
            "sha256":          self.sha256,
            "parent_sha256":   self.parent_sha256,
            "log_count":       self.log_count,
            "source":          self.source,
            "payload_preview": self.payload_preview,
            "created_at":      self.created_at.isoformat() if self.created_at else None,
        }
