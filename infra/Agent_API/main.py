"""
AgentAPI — service de réponse SOAR déployé sur chaque machine surveillée.

Reçoit les ordres de blocage/déblocage émis par le SIEM backend suite au
déclenchement d'une règle de corrélation, et exécute le blocage réseau
localement (iptables sous Linux, netsh sous Windows).

Démarrage :
    export AGENTAPI_TOKEN=$(python -c "import secrets; print(secrets.token_hex(32))")
    export AGENTAPI_ALLOWED_CALLERS=10.0.0.5
    uvicorn main:app --host 0.0.0.0 --port 9000

Voir README.md pour le déploiement complet et les tests locaux en HTTP.
"""
from fastapi import Depends, FastAPI, HTTPException, status

try:
    from . import audit, config, firewall, scheduler, state
    from .models import (
        ActionMode,
        ActionResult,
        BlockRequest,
        BlockResponse,
        UnblockRequest,
    )
    from .security import enforce_security
except ImportError:  # pragma: no cover - fallback for direct execution
    import audit
    import config
    import firewall
    import scheduler
    import state
    from models import (  # type: ignore
        ActionMode,
        ActionResult,
        BlockRequest,
        BlockResponse,
        UnblockRequest,
    )
    from security import enforce_security

config.validate_config()

app = FastAPI(
    title="Smart SIEM — AgentAPI",
    description="Agent de réponse SOAR (blocage réseau) déployé sur les machines surveillées",
    version="1.0.0",
)


@app.get("/health")
def health():
    """Endpoint non authentifié — juste pour les checks de disponibilité (pas d'info sensible)."""
    return {"status": "ok", "os": firewall.get_os()}


@app.post("/block", response_model=BlockResponse, dependencies=[Depends(enforce_security)])
async def block(req: BlockRequest):
    """
    Bloque attacker_ip immédiatement (mode AUTO implicite pour l'attaquant).
    Bloque victim_ip selon req.victim_mode (AUTO ou CONFIRM avec délai).
    """
    results = []

    # --- IP attaquante : toujours bloquée immédiatement, c'est le cœur du playbook ---
    try:
        if state.is_blocked(req.attacker_ip):
            audit.record("block", req.attacker_ip, "noop", req.incident_id, req.rule_id,
                         "Déjà bloquée")
            results.append(ActionResult(status="already_blocked", ip=req.attacker_ip,
                                         detail="IP attaquante déjà bloquée"))
        else:
            firewall.block_ip(req.attacker_ip)
            state.add_blocked(req.attacker_ip, req.incident_id, req.rule_id, req.reason)
            audit.record("block", req.attacker_ip, "success", req.incident_id, req.rule_id, req.reason)
            results.append(ActionResult(status="executed", ip=req.attacker_ip,
                                         detail="IP attaquante bloquée"))
    except firewall.FirewallError as exc:
        audit.record("block", req.attacker_ip, "failure", req.incident_id, req.rule_id, str(exc))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                             detail=f"Échec du blocage de l'IP attaquante: {exc}")

    # --- IP victime (optionnelle) : selon le mode demandé ---
    if req.victim_ip:
        if req.victim_mode == ActionMode.AUTO:
            try:
                if state.is_blocked(req.victim_ip):
                    results.append(ActionResult(status="already_blocked", ip=req.victim_ip,
                                                 detail="IP victime déjà bloquée"))
                else:
                    firewall.block_ip(req.victim_ip)
                    state.add_blocked(req.victim_ip, req.incident_id, req.rule_id, req.reason)
                    audit.record("block", req.victim_ip, "success", req.incident_id, req.rule_id, req.reason)
                    results.append(ActionResult(status="executed", ip=req.victim_ip,
                                                 detail="IP victime bloquée (mode AUTO)"))
            except firewall.FirewallError as exc:
                audit.record("block", req.victim_ip, "failure", req.incident_id, req.rule_id, str(exc))
                results.append(ActionResult(status="failure", ip=req.victim_ip, detail=str(exc)))
        else:  # CONFIRM
            def _executor(ip: str) -> None:
                firewall.block_ip(ip)
                state.add_blocked(ip, req.incident_id, req.rule_id, req.reason)

            action = scheduler.schedule(
                req.victim_ip, req.incident_id, req.reason, req.rule_id, _executor
            )
            results.append(ActionResult(
                status="scheduled", ip=req.victim_ip, action_id=action.action_id,
                detail=f"Blocage planifié dans {config.CONFIRM_DELAY_SECONDS}s, annulable via /confirm/{{action_id}}/cancel",
            ))

    return BlockResponse(results=results)


@app.post("/unblock", response_model=ActionResult, dependencies=[Depends(enforce_security)])
def unblock(req: UnblockRequest):
    """Lève un blocage. Idempotent : débloquer une IP non bloquée n'est pas une erreur."""
    try:
        firewall.unblock_ip(req.ip)
    except firewall.FirewallError as exc:
        audit.record("unblock", req.ip, "failure", req.incident_id, reason=str(exc))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                             detail=f"Échec du déblocage: {exc}")

    was_tracked = state.remove_blocked(req.ip)
    audit.record("unblock", req.ip, "success", req.incident_id, reason=req.reason)
    return ActionResult(
        status="executed", ip=req.ip,
        detail="IP débloquée" if was_tracked else "IP débloquée (n'était pas dans le registre local)",
    )


@app.post("/confirm/{action_id}/cancel", dependencies=[Depends(enforce_security)])
def cancel_pending(action_id: str):
    """Annule une action planifiée en mode CONFIRM avant son exécution."""
    cancelled = scheduler.cancel(action_id)
    if not cancelled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                             detail="Action introuvable ou déjà exécutée")
    return {"status": "cancelled", "action_id": action_id}


@app.get("/status", dependencies=[Depends(enforce_security)])
def get_status():
    """Vue d'ensemble : IPs actuellement bloquées + actions CONFIRM en attente."""
    return {
        "blocked": state.list_blocked(),
        "pending_confirm": [
            {
                "action_id": a.action_id,
                "ip": a.ip,
                "incident_id": a.incident_id,
                "reason": a.reason,
                "scheduled_at": a.scheduled_at.isoformat(),
                "executes_at": a.executes_at.isoformat(),
            }
            for a in scheduler.list_pending()
        ],
    }


@app.get("/audit", dependencies=[Depends(enforce_security)])
def get_audit(limit: int = 100):
    """Journal d'audit récent — pour la traçabilité exigée par le cahier des charges."""
    return {"entries": audit.read_recent(limit)}
