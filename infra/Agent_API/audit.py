"""
Journal d'audit append-only.

Chaque action (blocage, déblocage, planification, annulation, échec)
est écrite en JSON Lines.

ce module permet d'avoir une trace de toutes les actions de sécurité effectuées 
par l'AgentAPI, pour audit et déboggage. Il est conçu pour ne jamais lever d'exception vers l'appelant métier,
afin de ne pas interrompre des actions critiques de sécurité en cas de problème de logging.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from . import config
except ImportError:  # pragma: no cover - fallback for direct execution
    import config


def _ensure_log_dir() -> None:
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)


def record(
    action: str,
    ip: Optional[str],
    result: str,
    incident_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    reason: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None,
) -> None:
    """Écrit une entrée d'audit. Ne lève jamais d'exception vers l'appelant métier —
    un problème de logging ne doit pas empêcher un blocage de sécurité critique,
    mais il est aussi loggé sur stderr pour ne pas passer inaperçu."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,       # "block" | "unblock" | "schedule" | "cancel" | "error"
        "ip": ip,
        "result": result,       # "success" | "failure" | "noop"
        "incident_id": incident_id,
        "rule_id": rule_id,
        "reason": reason,
        "extra": extra or {},
    }
    try:
        _ensure_log_dir()
        with open(config.AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:
        print(f"[AUDIT LOGGING FAILED] {entry} -- error: {exc}")


def read_recent(limit: int = 100) -> list[dict[str, Any]]:
    if not config.AUDIT_LOG_FILE.exists():
        return []
    lines = config.AUDIT_LOG_FILE.read_text(encoding="utf-8").strip().splitlines()
    recent = lines[-limit:]
    return [json.loads(line) for line in recent]
