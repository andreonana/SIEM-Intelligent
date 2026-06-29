# ============================================================
# actions.py — SOAR Playbook Actions
# Contains the 3 automated response functions
# Used by: playbook_engine.py calls these when a rule fires
# ============================================================

import os
from datetime import datetime
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from app.modules.rbac.auth import create_access_token

load_dotenv()

ES_HOST = os.getenv("ES_HOST", "localhost")
ES_PORT = os.getenv("ES_PORT", "9200")
ES_USE_SSL = os.getenv("ES_USE_SSL", "false").lower() == "true"
INDEX_AUDIT = os.getenv("ES_INDEX_AUDIT", "siem-audit")

es = Elasticsearch(
    f"{'https' if ES_USE_SSL else 'http'}://{ES_HOST}:{ES_PORT}",
    verify_certs=False
)

def _write_audit(action: str, target: str, result: str,
                 alert_id: str, triggered_by: str = "system"):
    """Writes every playbook action to the audit trail."""
    es.index(index=INDEX_AUDIT, document={
        "action":       action,
        "target":       target,
        "result":       result,
        "alert_id":     alert_id,
        "username":     triggered_by,
        "timestamp":    datetime.utcnow().isoformat(),
    })

# ── Playbook 1 — Block IP (AUTO) ──────────────────────────
def block_ip(source_ip: str, alert_id: str,
             triggered_by: str = "auto_correlation") -> dict:
    """
    Blocks a source IP address immediately.

    In a real environment this would call the firewall API.
    For the demo it logs the action and returns success.

    Usage (called automatically by playbook_engine.py):
        result = block_ip("178.43.12.87", "CTU-2026-0847")
    """
    try:
        # In production: call firewall API here
        # requests.post("http://firewall/api/block", json={"ip": source_ip})

        result_msg = f"IP {source_ip} blocked on firewall"
        _write_audit(
            action="block_ip",
            target=source_ip,
            result=result_msg,
            alert_id=alert_id,
            triggered_by=triggered_by,
        )
        print(f"[SOAR] {result_msg}")
        return {"status": "success", "action": "block_ip",
                "target": source_ip, "message": result_msg}

    except Exception as e:
        error_msg = f"Failed to block IP {source_ip}: {str(e)}"
        _write_audit("block_ip", source_ip, f"ERROR: {error_msg}",
                     alert_id, triggered_by)
        return {"status": "error", "message": error_msg}


# ── Playbook 2 — Disable Account (CONFIRM) ───────────────
def disable_account(username: str, alert_id: str,
                    triggered_by: str = "auto_correlation",
                    skip_delay: bool = False) -> dict:
    """
    Disables a user account in Elasticsearch.

    For internal CTU accounts: waits 60 seconds before acting
    to allow an analyst to cancel (CONFIRM mode).
    For external/service accounts: acts immediately (AUTO).

    Usage:
        result = disable_account("CTU-SVC-003", "CTU-2026-0848")
    """
    import time

    try:
        # 60-second delay for internal accounts (CONFIRM mode)
        is_internal = username.startswith("CTU-")
        if is_internal and not skip_delay:
            print(f"[SOAR] CONFIRM mode: waiting 60s before disabling {username}")
            print(f"[SOAR] Send POST /api/soar/cancel/{alert_id} to abort")
            time.sleep(60)

        # Disable in Elasticsearch siem-users index
        index_users = os.getenv("ES_INDEX_USERS", "siem-users")
        result_es = es.update_by_query(
            index=index_users,
            body={
                "script": {
                    "source": "ctx._source.is_active = false",
                    "lang": "painless"
                },
                "query": {
                    "term": {"username": username}
                }
            }
        )

        result_msg = f"Account {username} disabled — {result_es.get('updated', 0)} record updated"
        _write_audit("disable_account", username, result_msg,
                     alert_id, triggered_by)
        print(f"[SOAR] {result_msg}")
        return {"status": "success", "action": "disable_account",
                "target": username, "message": result_msg}

    except Exception as e:
        error_msg = f"Failed to disable account {username}: {str(e)}"
        _write_audit("disable_account", username, f"ERROR: {error_msg}",
                     alert_id, triggered_by)
        return {"status": "error", "message": error_msg}


# ── Playbook 3 — Escalate to Admin (AUTO) ────────────────
def escalate_admin(alert_id: str, alert_name: str,
                   severity: str, source_ip: str = "",
                   triggered_by: str = "auto_correlation") -> dict:
    """
    Notifies the on-call administrator via webhook and email.

    Sends immediately — no delay.
    Reads ONCALL_ADMIN_EMAIL and SLACK_WEBHOOK_URL from .env

    Usage:
        result = escalate_admin(
            alert_id="CTU-2026-0847",
            alert_name="SSH Brute-Force Detected",
            severity="CRITICAL",
            source_ip="178.43.12.87"
        )
    """
    import requests
    import smtplib
    from email.mime.text import MIMEText

    results = []

    # ── Webhook notification (Slack / Teams) ──────────────
    webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
    if webhook_url:
        try:
            payload = {
                "text": (
                    f"🚨 *{severity} ALERT* — {alert_name}\n"
                    f"Alert ID: {alert_id}\n"
                    f"Source: {source_ip or 'N/A'}\n"
                    f"Time: {datetime.utcnow().isoformat()}\n"
                    f"Action required immediately."
                )
            }
            r = requests.post(webhook_url, json=payload, timeout=10)
            results.append(f"Webhook: {r.status_code}")
        except Exception as e:
            results.append(f"Webhook failed: {str(e)}")

    # ── Email notification ────────────────────────────────
    smtp_host = os.getenv("SMTP_HOST", "")
    if smtp_host:
        try:
            msg = MIMEText(
                f"SMART SIEM ALERT\n\n"
                f"Alert: {alert_name}\n"
                f"Severity: {severity}\n"
                f"Alert ID: {alert_id}\n"
                f"Source IP: {source_ip or 'N/A'}\n"
                f"Time: {datetime.utcnow().isoformat()}\n\n"
                f"Please log into the SIEM immediately."
            )
            msg["Subject"] = f"[SMART SIEM] {severity} — {alert_name}"
            msg["From"] = os.getenv("SMTP_USER", "siem@ctu.gov")
            msg["To"]   = os.getenv("ONCALL_ADMIN_EMAIL", "admin@ctu.gov")

            with smtplib.SMTP(smtp_host,
                              int(os.getenv("SMTP_PORT", "587"))) as server:
                server.starttls()
                server.login(os.getenv("SMTP_USER", ""),
                             os.getenv("SMTP_PASS", ""))
                server.send_message(msg)
            results.append("Email: sent")
        except Exception as e:
            results.append(f"Email failed: {str(e)}")

    result_msg = f"Escalation sent — {', '.join(results)}"
    _write_audit("escalate_admin",
                 os.getenv("ONCALL_ADMIN_EMAIL", "admin"),
                 result_msg, alert_id, triggered_by)
    print(f"[SOAR] {result_msg}")
    return {"status": "success", "action": "escalate_admin",
            "message": result_msg, "channels": results}