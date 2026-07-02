# Enregistre tous les modèles SQLAlchemy pour que Base.metadata les connaisse
from app.models.user import User  # noqa: F401
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.alert import Alert  # noqa: F401
from app.models.rule import CorrelationRule  # noqa: F401
from app.models.playbook_execution import PlaybookExecution  # noqa: F401
from app.models.ueba_anomaly import UEBAAnomaly  # noqa: F401
from app.models.ueba_risk_score import UEBARiskScore  # noqa: F401
from app.models.log_batch import LogBatch  # noqa: F401
from app.models.investigation_flag import InvestigationFlag  # noqa: F401
