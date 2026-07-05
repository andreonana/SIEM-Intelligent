"""
Exemple d'appel de l'AgentAPI depuis le SIEM backend, en HTTP simple.

Ce fichier vit côté SIEM backend, PAS sur les machines agents.
Nécessite : pip install requests
"""
import requests

AGENT_TOKEN = "REMPLACER_PAR_LE_TOKEN_PARTAGE"  # cf. AGENTAPI_TOKEN de l'agent visé


def trigger_block(agent_host: str, agent_port: int, attacker_ip: str,
                   incident_id: str, reason: str,
                   victim_ip: str | None = None, victim_mode: str = "confirm") -> dict:
    url = f"http://{agent_host}:{agent_port}/block"
    payload = {
        "attacker_ip": attacker_ip,
        "incident_id": incident_id,
        "reason": reason,
    }
    if victim_ip:
        payload["victim_ip"] = victim_ip
        payload["victim_mode"] = victim_mode

    response = requests.post(
        url,
        json=payload,
        headers={"X-API-Key": AGENT_TOKEN},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = trigger_block(
        agent_host="127.0.0.1",
        agent_port=9000,
        attacker_ip="203.0.113.10",
        victim_ip="127.0.0.1",
        victim_mode="confirm",
        incident_id="inc-2026-07-02-0042",
        reason="5 échecs SSH en 60s (T1110)",
    )
    print(result)
