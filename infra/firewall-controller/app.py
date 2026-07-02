# infra/firewall-controller/app.py
#
# Service firewall réel pour le Smart SIEM.
#
# Ce service expose une API HTTP minimale consommée par le backend (playbook
# SOAR `block_ip`, voir backend/app/modules/soar/playbooks.py). Il ne simule
# rien : chaque appel à POST /block exécute réellement une commande `iptables`
# dans le network namespace de CE conteneur, via subprocess.
#
# Portée réelle du blocage (à documenter en soutenance)
# ------------------------------------------------------
# Ce contrôleur applique la règle `iptables` dans SON PROPRE espace réseau
# Linux (celui du conteneur `firewall-controller`), pas sur l'hôte Docker ni
# sur les autres conteneurs de la stack. C'est un firewall réel et
# fonctionnel, démontrable de bout en bout (la commande s'exécute
# effectivement, la règle apparaît dans `iptables -L`, et un second appel sur
# la même IP est idempotent), mais il ne protège que ce conteneur lui-même,
# pas l'infrastructure hôte. Pour une isolation réseau qui affecterait
# réellement les autres services (ex: bloquer une IP qui attaque
# `syslog-receiver`), il faudrait exécuter ce contrôleur en `network_mode:
# host` avec les capacités NET_ADMIN sur l'hôte — un choix délibérément écarté
# ici pour ne pas exiger un accès privilégié à l'hôte Docker du projet.
#
# Permissions requises
# ---------------------
# Le conteneur doit disposer de la capability Linux NET_ADMIN (voir
# docker-compose.yml : `cap_add: [NET_ADMIN]`) pour que `iptables` puisse
# modifier les règles de filtrage. Sans cette capability, iptables échoue
# avec "Permission denied" — ce service ne masque jamais cette erreur : elle
# est renvoyée telle quelle dans le champ "error" de la réponse HTTP.

import ipaddress
import logging
import subprocess
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, field_validator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("firewall-controller")

app = FastAPI(
    title="Smart SIEM — Firewall Controller",
    description="Service de blocage d'IP réel (iptables) pour le playbook SOAR block_ip.",
    version="1.0.0",
)

# Registre en mémoire des IP bloquées par ce contrôleur, pour audit/idempotence
# et pour l'endpoint de consultation GET /blocked. Redémarrer le service
# réinitialise ce registre (les règles iptables, elles, ne persistent que le
# temps de vie du conteneur également, puisqu'aucun volume n'est utilisé).
_blocked_ips: dict[str, dict] = {}


class BlockRequest(BaseModel):
    ip: str
    reason: str = ""

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        # Validation stricte avant toute exécution shell : élimine tout risque
        # d'injection de commande via un champ "ip" malformé.
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"Adresse IP invalide: {value}") from exc
        return value


@app.get("/health")
async def health():
    """Vérifie que iptables est exécutable dans ce conteneur (sans modifier de règle)."""
    try:
        result = subprocess.run(
            ["iptables", "-L", "-n"],
            capture_output=True, text=True, timeout=5,
        )
        iptables_ok = result.returncode == 0
    except Exception as exc:
        return {"status": "degraded", "iptables_available": False, "error": str(exc)}

    return {
        "status": "healthy" if iptables_ok else "degraded",
        "iptables_available": iptables_ok,
        "blocked_count": len(_blocked_ips),
    }


@app.post("/block")
async def block_ip(body: BlockRequest):
    """
    Bloque réellement une adresse IP via iptables (DROP sur INPUT).
    Réponse :
      succès : {"status": "blocked", "ip": "..."}
      échec  : {"status": "failure", "ip": "...", "error": "..."}  (HTTP 200 — l'échec est une donnée métier, pas une erreur de transport)
    """
    ip = body.ip
    reason = body.reason

    if ip in _blocked_ips:
        logger.info("[firewall-controller] IP %s déjà bloquée (idempotent).", ip)
        return {"status": "blocked", "ip": ip, "detail": "déjà bloquée"}

    try:
        result = subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5,
        )
    except FileNotFoundError as exc:
        error = f"Commande 'iptables' introuvable dans ce conteneur: {exc}"
        logger.error("[firewall-controller] %s", error)
        return {"status": "failure", "ip": ip, "error": error}
    except subprocess.TimeoutExpired as exc:
        error = f"Timeout lors de l'exécution d'iptables: {exc}"
        logger.error("[firewall-controller] %s", error)
        return {"status": "failure", "ip": ip, "error": error}

    if result.returncode != 0:
        error = result.stderr.strip() or f"iptables a retourné le code {result.returncode}"
        logger.error("[firewall-controller] Échec du blocage de %s: %s", ip, error)
        return {"status": "failure", "ip": ip, "error": error}

    _blocked_ips[ip] = {
        "reason": reason,
        "blocked_at": datetime.now(timezone.utc).isoformat(),
    }
    logger.info("[firewall-controller] IP %s bloquée réellement via iptables. Raison: %s", ip, reason)
    return {"status": "blocked", "ip": ip}


@app.get("/blocked")
async def list_blocked():
    """Liste les IP bloquées par ce contrôleur depuis son démarrage (audit/démo)."""
    return {"total": len(_blocked_ips), "blocked": _blocked_ips}


@app.delete("/block/{ip}")
async def unblock_ip(ip: str):
    """Retire une règle de blocage (utile pour les tests et les démonstrations)."""
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Adresse IP invalide: {ip}") from exc

    if ip not in _blocked_ips:
        raise HTTPException(status_code=404, detail=f"{ip} n'est pas bloquée par ce contrôleur.")

    result = subprocess.run(
        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode != 0:
        error = result.stderr.strip() or f"iptables a retourné le code {result.returncode}"
        raise HTTPException(status_code=500, detail=f"Échec du déblocage: {error}")

    del _blocked_ips[ip]
    return {"status": "unblocked", "ip": ip}
