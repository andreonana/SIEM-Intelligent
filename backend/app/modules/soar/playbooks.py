# backend/app/modules/soar/playbooks.py
#
# Playbooks SOAR S2 : block_ip, disable_account, escalate_admin.

import json
import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.playbook_execution import PlaybookExecution
from app.modules.alerting.notifier import send_webhook, send_email
from app.services.audit_service import log_action
from app.services.user_service import get_user_by_username

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _persist_execution(
    db: AsyncSession,
    playbook_id: str,
    triggered_by: str,
    params: dict,
    result: dict,
    status: str,
    alert_id: int | None = None,
) -> PlaybookExecution:
    execution = PlaybookExecution(
        playbook_id=playbook_id,
        alert_id=alert_id,
        triggered_by=triggered_by,
        params=json.dumps(params),
        result=json.dumps(result),
        status=status,
        executed_at=datetime.now(timezone.utc),
    )
    db.add(execution)
    await db.commit()
    await db.refresh(execution)
    return execution


# ---------------------------------------------------------------------------
# Playbook: block_ip
# ---------------------------------------------------------------------------

async def _run_block_ip(params: dict, triggered_by: str, db: AsyncSession) -> dict:
    from app.core.config import settings

    ip = params.get("ip", "")
    reason = params.get("reason", "")
    alert_id = params.get("alert_id")

    logger.info("[SOAR] block_ip: ip=%s reason=%s triggered_by=%s", ip, reason, triggered_by)

    if not settings.firewall_api_url:
        # Aucun pare-feu réel configuré : on ne prétend jamais avoir bloqué l'IP.
        # Échec explicite et journalisé, jamais un faux succès "simulated".
        error = "FIREWALL_API_URL non configuré — aucune intégration pare-feu réelle disponible."
        logger.error("[SOAR] block_ip: %s (ip=%s)", error, ip)
        result = {"status": "failure", "ip": ip, "error": error}
        await _persist_execution(db, "block_ip", triggered_by, params, result, "failure", alert_id)
        await log_action(db, triggered_by, "playbook_run", target="block_ip", detail=json.dumps(result), result="failure")
        return result

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{settings.firewall_api_url}/block",
                json={"ip": ip, "reason": reason},
            )
            resp.raise_for_status()
            body = resp.json()
    except Exception as exc:
        # Erreur de transport : firewall injoignable, timeout, HTTP 4xx/5xx...
        error = f"Appel à l'API firewall échoué: {exc}"
        logger.error("[SOAR] block_ip: %s", error)
        result = {"status": "failure", "ip": ip, "error": error}
        await _persist_execution(db, "block_ip", triggered_by, params, result, "failure", alert_id)
        await log_action(db, triggered_by, "playbook_run", target="block_ip", detail=json.dumps(result), result="failure")
        return result

    # Le firewall a répondu HTTP 2xx : on ne présume jamais du succès sans lire
    # son corps de réponse réel (un HTTP 200 ne garantit pas status=blocked).
    if body.get("status") != "blocked":
        error = body.get("error") or f"Réponse inattendue du firewall: {body}"
        logger.error("[SOAR] block_ip: le firewall a refusé le blocage de %s: %s", ip, error)
        result = {"status": "failure", "ip": ip, "error": error}
        await _persist_execution(db, "block_ip", triggered_by, params, result, "failure", alert_id)
        await log_action(db, triggered_by, "playbook_run", target="block_ip", detail=json.dumps(result), result="failure")
        return result

    result = {"status": "blocked", "ip": ip}
    await _persist_execution(db, "block_ip", triggered_by, params, result, "success", alert_id)
    await log_action(db, triggered_by, "playbook_run", target="block_ip", detail=json.dumps(result), result="success")
    return result


# ---------------------------------------------------------------------------
# Playbook: disable_account
# ---------------------------------------------------------------------------

async def _run_disable_account(params: dict, triggered_by: str, db: AsyncSession) -> dict:
    username = params.get("username", "")
    reason = params.get("reason", "")
    alert_id = params.get("alert_id")

    logger.info("[SOAR] disable_account: username=%s triggered_by=%s", username, triggered_by)

    user = await get_user_by_username(db, username)
    if user is None:
        result = {"status": "user_not_found", "username": username}
        await _persist_execution(db, "disable_account", triggered_by, params, result, "failure", alert_id)
        await log_action(db, triggered_by, "playbook_run", target="disable_account", detail=json.dumps(result))
        return result

    user.is_active = False
    await db.commit()

    result = {"status": "disabled", "username": username}
    await _persist_execution(db, "disable_account", triggered_by, params, result, "success", alert_id)
    await log_action(db, triggered_by, "playbook_run", target="disable_account", detail=json.dumps(result))
    await log_action(db, triggered_by, "disable_user", target=username, detail=f"reason={reason}")
    return result


# ---------------------------------------------------------------------------
# Playbook: escalate_admin
# ---------------------------------------------------------------------------

async def _run_escalate_admin(params: dict, triggered_by: str, db: AsyncSession) -> dict:
    from app.core.config import settings

    reason = params.get("reason", "")
    alert_id = params.get("alert_id")
    severity = params.get("severity", "HIGH")

    logger.info("[SOAR] escalate_admin: severity=%s triggered_by=%s", severity, triggered_by)

    message = (
        f"[ESCALADE ADMIN] Alerte {severity} requiert une attention immédiate.\n"
        f"Raison: {reason}\n"
        f"Alert ID: {alert_id}\n"
        f"Déclenché par: {triggered_by}"
    )

    channels_notified = []

    if settings.slack_webhook_url:
        ok = await send_webhook(settings.slack_webhook_url, {"text": message})
        if ok:
            channels_notified.append("slack")

    if settings.teams_webhook_url:
        ok = await send_webhook(settings.teams_webhook_url, {"text": message})
        if ok:
            channels_notified.append("teams")

    if settings.alert_email_to:
        ok = await send_email(
            to=settings.alert_email_to,
            subject=f"[SIEM ESCALADE] {severity} — Action admin requise",
            body=message,
        )
        if ok:
            channels_notified.append("email")

    result = {"status": "escalated", "channels_notified": channels_notified}
    await _persist_execution(db, "escalate_admin", triggered_by, params, result, "success", alert_id)
    await log_action(db, triggered_by, "playbook_run", target="escalate_admin", detail=json.dumps(result))
    return result


# ---------------------------------------------------------------------------
# Registre et dispatcher
# ---------------------------------------------------------------------------

PLAYBOOKS = {
    "block_ip": {
        "id":          "block_ip",
        "name":        "Block IP",
        "description": "Bloque réellement une adresse IP via l'API firewall configurée (FIREWALL_API_URL). Retourne 'failure' avec une erreur explicite si la config est absente ou si le blocage échoue — jamais de succès simulé.",
        "params":      ["ip", "reason", "alert_id"],
    },
    "disable_account": {
        "id":          "disable_account",
        "name":        "Disable Account",
        "description": "Désactive le compte d'un utilisateur du SIEM.",
        "params":      ["username", "reason", "alert_id"],
    },
    "escalate_admin": {
        "id":          "escalate_admin",
        "name":        "Escalate to Admin",
        "description": "Envoie une escalade urgente aux administrateurs via webhook et email.",
        "params":      ["reason", "alert_id", "severity"],
    },
}

_HANDLERS = {
    "block_ip":        _run_block_ip,
    "disable_account": _run_disable_account,
    "escalate_admin":  _run_escalate_admin,
}


async def run_playbook(
    playbook_id: str,
    params: dict,
    triggered_by: str,
    db: AsyncSession,
    es_client=None,
) -> dict:
    """Exécute un playbook par son identifiant. Lève ValueError si inconnu."""
    if playbook_id not in _HANDLERS:
        raise ValueError(f"Playbook inconnu: '{playbook_id}'. Disponibles: {list(PLAYBOOKS)}")
    return await _HANDLERS[playbook_id](params, triggered_by, db)
