# ============================================================
# retention.py — Automatic Log Retention & Cleanup
# Handles: deleting logs older than RETENTION_DAYS
# Used by: backend dev includes this router in main.py
#          and schedules the cleanup job
# ============================================================

import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from fastapi import APIRouter, Depends
from apscheduler.schedulers.background import BackgroundScheduler
from app.modules.rbac.roles import require_role

load_dotenv()

# ── Setup ─────────────────────────────────────────────────
router = APIRouter()

# ── Elasticsearch connection over HTTPS ───────────────────
ES_HOST = os.getenv("ES_HOST", "localhost")
ES_PORT = os.getenv("ES_PORT", "9200")
ES_USE_SSL = os.getenv("ES_USE_SSL", "false").lower() == "true"

es = Elasticsearch(
    f"{'https' if ES_USE_SSL else 'http'}://{ES_HOST}:{ES_PORT}",
    verify_certs=False  # False for self-signed certificate
)

INDEX_LOGS     = os.getenv("ES_INDEX_LOGS",  "siem-logs")
INDEX_AUDIT    = os.getenv("ES_INDEX_AUDIT", "siem-audit")
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))

# ── Core Cleanup Function ─────────────────────────────────
def run_retention_cleanup() -> dict:
    """
    Deletes all logs older than RETENTION_DAYS from Elasticsearch.
    Also writes an entry to the audit log so there's a record.
    Returns a summary dict with how many logs were deleted.
    """
    cutoff_date = datetime.utcnow() - timedelta(days=RETENTION_DAYS)

    print(f"[Retention] Running cleanup. Deleting logs before {cutoff_date.isoformat()}")

    # Delete old logs from Elasticsearch
    response = es.delete_by_query(
        index=INDEX_LOGS,
        body={
            "query": {
                "range": {
                    "timestamp": {
                        "lt": cutoff_date.isoformat()
                    }
                }
            }
        }
    )

    deleted_count = response.get("deleted", 0)
    print(f"[Retention] Deleted {deleted_count} documents.")

    # Write to audit log — security trail
    es.index(
        index=INDEX_AUDIT,
        document={
            "action":    "retention_cleanup",
            "target":    f"{INDEX_LOGS} — logs older than {RETENTION_DAYS} days",
            "result":    f"deleted {deleted_count} documents",
            "timestamp": datetime.utcnow().isoformat(),
            "username":  "system",
        }
    )

    return {
        "deleted":        deleted_count,
        "cutoff":         cutoff_date.isoformat(),
        "retention_days": RETENTION_DAYS
    }

# ── Scheduled Job ─────────────────────────────────────────
def start_retention_scheduler():
    """
    Starts a background job that runs cleanup every day at 2 AM.

    Backend dev adds this to main.py:
        from app.modules.rbac.retention import start_retention_scheduler
        start_retention_scheduler()
    """
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_retention_cleanup,
        trigger="cron",
        hour=2,
        minute=0,
        id="daily_retention_cleanup"
    )
    scheduler.start()
    print("[Retention] Scheduler started — cleanup runs daily at 02:00")

# ── Manual Trigger Endpoint ───────────────────────────────
@router.post(
    "/api/admin/retention/run",
    summary="Manually trigger log retention cleanup",
    tags=["Security"]
)
def trigger_retention_manually(
    user=Depends(require_role("administrator"))
):
    """
    Only administrators can trigger this.
    Useful for demonstrating the retention policy during the defense.
    """
    result = run_retention_cleanup()
    return {
        "status":       "cleanup complete",
        "triggered_by": user["username"],
        **result
    }
