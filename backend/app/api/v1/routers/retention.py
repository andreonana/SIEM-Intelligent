# ── Manual Trigger Endpoint ───────────────────────────────
# This is for the demo: run cleanup on demand without waiting 24h
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
        "status": "cleanup complete",
        "triggered_by": user["username"],
        **result
    }