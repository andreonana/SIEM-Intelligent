#   backend/app/modules/rbac/retention.py
#
#   Role: 

# ============================================================
# retention.py — Automatic Log Retention & Cleanup
# Handles: deleting logs older than RETENTION_DAYS
# Used by: backend dev includes this router in main.py
#          and schedules the cleanup job
# ============================================================

from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from elasticsearch import AsyncElasticsearch

from app.core.config import settings
from app.db.elasticsearch_client import get_es_client

# ── Core Cleanup Function ─────────────────────────────────
async def run_retention_cleanup(es_client: AsyncElasticsearch | None = None,) -> dict:
    """
    Deletes all logs older than RETENTION_DAYS from Elasticsearch.
    Also writes an entry to the audit log so there's a record.
    
    Returns a summary dict with how many logs were deleted.
    """
    if es_client is None:
        es_client = get_es_client()

    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.retention_days)
    
    print(f"[Retention] Running cleanup. Deleting logs before {cutoff.isoformat()}")
    
    try:
        # Elasticsearch Delete by Query
        # This deletes every document in siem-logs
        # where the timestamp is older than our cutoff
        response = await es_client.delete_by_query(
            index=settings.es_logs_index_name,
            body={
                "query": {
                    "range": {
                        "timestamp": {
                            "lt": cutoff.isoformat()
                        }
                    }
                }
            },
            refresh=True,
        )        
        deleted_count = response.get("deleted", 0)
    except Exception as exc:
        print(f"[Retention] Error in deleting: {exc}.")
        delete_cunt = 0

    print(f"[Retention] Deleted {deleted_count} documents.")
    
    try:
        # Write to audit log — this is the security trail
        await es_client.index(
            index=settings.es_audit_index_name,
            document={
                "action":    "retention_cleanup",
                "target":    f"{settings.es_logs_index_name} — logs older than {settings.retention_days} days",
                "result":    f"deleted {deleted_count} documents",
                "cuttoff":   cutoff.isoformat(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "username":  "system",  # Automated action, not a user
            },
        )
    except Exception as exc:
        print(f"[Retention] Impossible to write audit log: {exc}.")
    
    return {
        "deleted": deleted_count,
        "cutoff": cutoff.isoformat(),
        "retention_days": settings.retention_days,
    }

# ── Scheduled Job ─────────────────────────────────────────
def start_retention_scheduler():
    """
    Starts a background job that runs cleanup every day at 2 AM.
    
    The backend dev calls this once in main.py:
        from retention import start_retention_scheduler
        start_retention_scheduler()
    """
    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        run_retention_cleanup,
        trigger="cron",
        hour=2,
        minute=0,
        id="daily_retention_cleanup",
        replace_existing=True,
    )
    scheduler.start()
    print("[Retention] Scheduler started — cleanup runs daily at 02:00 UTC (retention: {settings.retention_days} days).")

