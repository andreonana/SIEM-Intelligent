# ============================================================
# triggers.py — Maps rules to playbooks
# ============================================================

from app.modules.soar.actions import (
    block_ip, disable_account, escalate_admin, isolate_machine
)

RULE_PLAYBOOK_MAP = {
    "brute_force":             ["block_ip"],
    "outside_hours":           ["escalate_admin"],
    "unauthorized_privileges": ["disable_account", "escalate_admin"],
    "communication_banned":    ["block_ip", "escalate_admin"],
    "log_hidden":              ["escalate_admin"],
}


def trigger_playbooks(rule_id: str, alert: dict) -> list:
    """
    Runs all playbooks linked to a triggered rule.
    Called by engine.py immediately after an alert is created.
    """
    playbooks = RULE_PLAYBOOK_MAP.get(rule_id, [])
    results = []

    for playbook in playbooks:
        if playbook == "block_ip":
            r = block_ip(
                source_ip=alert.get("source_ips", ["unknown"])[0],
                alert_id=alert.get("alert_id", ""),
            )
            results.append(r)

        elif playbook == "disable_account":
            r = disable_account(
                username=alert.get("username", ""),
                alert_id=alert.get("alert_id", ""),
            )
            results.append(r)

        elif playbook == "isolate_machine":
            r = isolate_machine(
                host=alert.get("hosts", ["unknown"])[0],
                alert_id=alert.get("alert_id", ""),
            )
            results.append(r)

        elif playbook == "escalate_admin":
            r = escalate_admin(
                alert_id=alert.get("alert_id", ""),
                alert_name=alert.get("rule_name", ""),
                severity=alert.get("severity", "CRITICAL"),
                source_ip=alert.get("source_ips", [""])[0],
            )
            results.append(r)

    return results
