# ============================================================
# permissions.py — Central Permission Rulebook
# Defines exactly which role is required for each action
# ============================================================

PERMISSIONS = {

    # ── Public (no role needed) ───────────────────────────
    "login":                    "public",
    "health_check":             "public",

    # ── Reader level ──────────────────────────────────────
    "view_logs":                "reader",
    "view_alerts":              "reader",
    "view_dashboard":           "reader",
    "view_reports":             "reader",
    "logout":                   "reader",

    # ── Analyst level ─────────────────────────────────────
    "acknowledge_alert":        "analyst",
    "search_logs":              "analyst",
    "view_investigation":       "analyst",
    "flag_event":               "analyst",
    "run_playbook":             "analyst",
    "view_playbooks":           "analyst",
    "view_rules":               "analyst",

    # ── Administrator level ───────────────────────────────
    "create_rule":              "administrator",
    "edit_rule":                "administrator",
    "delete_rule":              "administrator",
    "create_user":              "administrator",
    "edit_user":                "administrator",
    "delete_user":              "administrator",
    "view_users":               "administrator",
    "view_audit_trail":         "administrator",
    "trigger_retention":        "administrator",
    "generate_report":          "administrator",
}

def get_required_role(action: str) -> str:
    """
    Returns the minimum role required for a given action.

    Usage:
        role = get_required_role("view_logs")
        # returns "reader"

        role = get_required_role("create_user")
        # returns "administrator"
    """
    return PERMISSIONS.get(action, "administrator")
