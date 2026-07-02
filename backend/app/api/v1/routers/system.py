# backend/app/api/v1/routers/system.py
#
# Endpoint de santé de l'infrastructure SIEM. Vérifie la disponibilité réelle
# des services connus de la stack (Elasticsearch, syslog-receiver, nginx) par
# des sondes réseau réelles, et l'état du backend lui-même. Le forwarder n'a
# pas de port exposé : son état est déduit indirectement de la fraîcheur du
# dernier log reçu (heartbeat applicatif), ce qui est documenté explicitement
# pour ne pas laisser croire à une vérification directe.

import asyncio
import logging
import socket
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from app.core.config import settings
from app.db.elasticsearch_client import get_es_client
from app.modules.rbac.roles import require_role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/system", tags=["system"])


async def _tcp_probe(host: str, port: int, timeout: float = 2.0) -> bool:
    """Sonde TCP réelle : tente d'ouvrir une connexion, sans supposer de protocole applicatif."""
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _check_elasticsearch() -> dict:
    try:
        es_client = get_es_client()
        health = await es_client.cluster.health()
        es_status = health.get("status", "unknown")
        mapped = {"green": "healthy", "yellow": "degraded", "red": "unavailable"}.get(es_status, "unknown")
        return {"name": "elasticsearch", "status": mapped, "detail": f"cluster_status={es_status}"}
    except Exception as exc:
        logger.warning("[SystemHealth] Elasticsearch injoignable: %s", exc)
        return {"name": "elasticsearch", "status": "unavailable", "detail": str(exc)}


async def _check_tcp_service(name: str, host: str, port: int) -> dict:
    reachable = await _tcp_probe(host, port)
    return {
        "name": name,
        "status": "healthy" if reachable else "unavailable",
        "detail": f"tcp_probe {host}:{port} {'reachable' if reachable else 'unreachable'}",
    }


async def _check_forwarder_heartbeat() -> dict:
    """
    Le forwarder n'expose aucun port réseau consultable par le backend.
    Vérification indirecte : présence d'un log reçu récemment (heartbeat applicatif).
    """
    try:
        es_client = get_es_client()
        resp = await es_client.search(
            index=settings.es_logs_index_name,
            size=1,
            sort=[{"received_at": {"order": "desc"}}],
        )
        hits = resp["hits"]["hits"]
        if not hits:
            return {
                "name": "forwarder",
                "status": "unknown",
                "detail": "Aucun log reçu — vérification indirecte impossible (aucun heartbeat).",
            }
        last_received = hits[0]["_source"].get("received_at")
        last_dt = datetime.fromisoformat(last_received.replace("Z", "+00:00"))
        age_minutes = (datetime.now(timezone.utc) - last_dt).total_seconds() / 60
        status = "healthy" if age_minutes < 15 else "degraded"
        return {
            "name": "forwarder",
            "status": status,
            "detail": f"Dernier log reçu il y a {age_minutes:.1f} min (vérification indirecte, pas de sonde directe).",
        }
    except Exception as exc:
        return {"name": "forwarder", "status": "unknown", "detail": f"Vérification indirecte impossible: {exc}"}


@router.get("/health")
async def get_system_health(user: dict = Depends(require_role("reader"))):
    """
    Retourne l'état réel des composants de l'infrastructure SIEM connus du backend :
    - backend : toujours "healthy" si cette route répond
    - elasticsearch : santé de cluster réelle (green/yellow/red)
    - syslog-receiver, nginx : sonde TCP réelle sur leur port exposé
    - forwarder : aucun port exposé, statut déduit indirectement de la fraîcheur du dernier log reçu
    Rôle requis: reader ou plus.
    """
    es_check, syslog_check, nginx_check, forwarder_check = await asyncio.gather(
        _check_elasticsearch(),
        _check_tcp_service("syslog-receiver", "siem-syslog-receiver", 8090),
        _check_tcp_service("nginx", "siem-nginx", 80),
        _check_forwarder_heartbeat(),
    )

    services = [
        {"name": "backend", "status": "healthy", "detail": "auto-vérification (cette réponse a été générée)"},
        es_check,
        syslog_check,
        nginx_check,
        forwarder_check,
    ]

    statuses = [s["status"] for s in services]
    if "unavailable" in statuses:
        overall = "degraded" if statuses.count("unavailable") < len(statuses) else "unavailable"
    elif "degraded" in statuses or "unknown" in statuses:
        overall = "degraded"
    else:
        overall = "healthy"

    return {"overall": overall, "services": services, "checked_at": datetime.now(timezone.utc).isoformat()}
