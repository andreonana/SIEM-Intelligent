"""
Gestion du mode CONFIRM.

Le cahier des charges impose un délai (60s par défaut) avant certaines
actions automatiques — typiquement bloquer une machine interne — pour
laisser une fenêtre d'annulation avant impact opérationnel.

Implémentation en mémoire avec asyncio : suffisant pour un agent qui
tourne en tant que service long-lived sur une seule machine. Si l'agent
redémarre pendant le délai, l'action planifiée est perdue — c'est un
compromis acceptable pour un projet étudiant, à documenter comme
limitation connue plutôt qu'à cacher.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

try:
    from . import audit, config
except ImportError:  # pragma: no cover - fallback for direct execution
    import audit
    import config


class PendingAction:
    def __init__(self, action_id: str, ip: str, incident_id: str, reason: str, rule_id: Optional[str]):
        self.action_id = action_id
        self.ip = ip
        self.incident_id = incident_id
        self.reason = reason
        self.rule_id = rule_id
        self.scheduled_at = datetime.now(timezone.utc)
        self.executes_at = self.scheduled_at + timedelta(seconds=config.CONFIRM_DELAY_SECONDS)
        self.task: Optional[asyncio.Task] = None
        self.cancelled = False


_pending: dict[str, PendingAction] = {}


async def _delayed_execute(action: PendingAction, executor: Callable[[str], None]) -> None:
    try:
        await asyncio.sleep(config.CONFIRM_DELAY_SECONDS)
        if action.cancelled:
            return
        executor(action.ip)
        audit.record(
            action="block", ip=action.ip, result="success",
            incident_id=action.incident_id, rule_id=action.rule_id,
            reason=action.reason, extra={"mode": "confirm", "action_id": action.action_id},
        )
    except Exception as exc:
        audit.record(
            action="block", ip=action.ip, result="failure",
            incident_id=action.incident_id, rule_id=action.rule_id,
            reason=str(exc), extra={"mode": "confirm", "action_id": action.action_id},
        )
    finally:
        _pending.pop(action.action_id, None)


def schedule(
    ip: str, incident_id: str, reason: str, rule_id: Optional[str],
    executor: Callable[[str], None],
) -> PendingAction:
    action_id = str(uuid.uuid4())
    action = PendingAction(action_id, ip, incident_id, reason, rule_id)
    action.task = asyncio.create_task(_delayed_execute(action, executor))
    _pending[action_id] = action
    audit.record(
        action="schedule", ip=ip, result="success",
        incident_id=incident_id, rule_id=rule_id, reason=reason,
        extra={"action_id": action_id, "executes_at": action.executes_at.isoformat()},
    )
    return action


def cancel(action_id: str) -> bool:
    action = _pending.get(action_id)
    if action is None:
        return False
    action.cancelled = True
    if action.task:
        action.task.cancel()
    _pending.pop(action_id, None)
    audit.record(
        action="cancel", ip=action.ip, result="success",
        incident_id=action.incident_id, reason="Annulé avant exécution",
        extra={"action_id": action_id},
    )
    return True


def list_pending() -> list[PendingAction]:
    return list(_pending.values())
