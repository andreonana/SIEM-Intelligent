# ============================================================
# rules.py — The 5 Correlation Rules
# Each rule tells the engine what to look for and when to fire
# Used by: engine.py loads these on startup
# ============================================================

from app.modules.correlation.mitre import BANNED_IPS, WORK_HOURS

THRESHOLD  = "threshold"
TIME_BASED = "time_based"
LIST_MATCH = "list_match"
PATTERN    = "pattern"

RULES = [

    # ── Rule 1 — Brute Force ──────────────────────────────
    {
        "id":          "brute_force",
        "name":        "Brute Force Attack",
        "label":       "brute force",
        "type":        THRESHOLD,
        "enabled":     True,
        "description": "5+ failed logins from same IP within 60 seconds.",
        "match": {
            "log_type": "auth",
            "keywords": ["Failed password", "Invalid user",
                         "Authentication failure", "Failed login"],
        },
        "threshold": {
            "count":      5,
            "window_sec": 60,
            "group_by":   "source_ip",
        },
        "alert": {
            "name":            "Brute Force Attack Detected",
            "severity":        "CRITICAL",
            "description":     "{count} failed login attempts from {source_ip} in {elapsed}s",
            "mitre_tactic":    "TA0001",
            "mitre_technique": "T1110",
        },
        "soar": {
            "playbook":     "block_ip",
            "mode":         "AUTO",
            "target_field": "source_ip",
        },
        "dedup": {
            "window_minutes": 5,
            "group_by": ["rule_id", "source_ip"],
        },
    },

    # ── Rule 2 — Outside Hours ────────────────────────────
    {
        "id":          "outside_hours",
        "name":        "Connection Outside Working Hours",
        "label":       "outside hours",
        "type":        TIME_BASED,
        "enabled":     True,
        "description": "Successful login outside 07:00-20:00 Mon-Fri or on weekends.",
        "match": {
            "log_type": "auth",
            "keywords": ["Accepted password", "session opened",
                         "logged in", "authentication success"],
        },
        "time_check": {
            "work_start":    WORK_HOURS["start"],
            "work_end":      WORK_HOURS["end"],
            "work_days":     WORK_HOURS["days"],
            "group_by":      "username",
            "whitelist_env": "OUTSIDE_HOURS_WHITELIST",
        },
        "alert": {
            "name":            "Off-Hours Login Detected",
            "severity":        "CRITICAL",
            "description":     "{username} logged in at {time} — outside working hours",
            "mitre_tactic":    "TA0001",
            "mitre_technique": "T1078",
        },
        "soar": {
            "playbook":     "escalate_admin",
            "mode":         "AUTO",
            "target_field": "username",
        },
        "dedup": {
            "window_minutes": 60,
            "group_by": ["rule_id", "username"],
        },
    },

    # ── Rule 3 — Unauthorized Privilege Modification ──────
    {
        "id":          "unauthorized_privileges",
        "name":        "Unauthorized Privilege Modification",
        "label":       "unauthorized privileges",
        "type":        PATTERN,
        "enabled":     True,
        "description": (
            "A privilege or role change was made by an account "
            "not in the approved administrators list."
        ),
        "match": {
            "log_type": ["auth", "system"],
            "keywords": [
                "sudo granted", "added to group sudo",
                "privilege granted", "admin rights added",
                "role changed to admin", "added to administrators",
                "usermod -aG sudo", "net localgroup administrators",
            ],
        },
        "pattern": {
            # The account making the change must NOT be in this env list
            "unauthorized_if_not_in_env": "APPROVED_ADMINS",
            "group_by": "username",
            # One event is enough
            "threshold": 1,
        },
        "alert": {
            "name":            "Unauthorized Privilege Modification",
            "severity":        "CRITICAL",
            "description":     "{username} granted elevated privileges without authorization",
            "mitre_tactic":    "TA0004",
            "mitre_technique": "T1098",
        },
        "soar": [
            {
                "playbook":     "disable_account",
                "mode":         "CONFIRM",
                "delay_sec":    60,
                "target_field": "username",
            },
            {
                "playbook":     "escalate_admin",
                "mode":         "AUTO",
                "target_field": "username",
            },
        ],
        "dedup": {
            "window_minutes": 10,
            "group_by": ["rule_id", "username"],
        },
    },

    # ── Rule 4 — Banned IP Communication ─────────────────
    {
        "id":          "communication_banned",
        "name":        "Communication with Malicious IP",
        "label":       "communication banned",
        "type":        LIST_MATCH,
        "enabled":     True,
        "description": "Any outbound connection to a known malicious IP address.",
        "match": {
            "log_type":  "network",
            "direction": "outbound",
        },
        "list_check": {
            "field":     "destination_ip",
            "list":      BANNED_IPS,
            "group_by":  "source_ip",
            "threshold": 1,
        },
        "alert": {
            "name":            "Communication with Banned Malicious IP",
            "severity":        "WARNING",
            "description":     "{source_ip} contacted banned IP {destination_ip}",
            "mitre_tactic":    "TA0011",
            "mitre_technique": "T1071",
        },
        "soar": [
            {
                "playbook":     "block_ip",
                "mode":         "AUTO",
                "target_field": "destination_ip",
            },
            {
                "playbook":     "escalate_admin",
                "mode":         "AUTO",
                "target_field": "source_ip",
            },
        ],
        "dedup": {
            "window_minutes": 5,
            "group_by": ["rule_id", "source_ip", "destination_ip"],
        },
    },

    # ── Rule 5 — Log Service Stopped ─────────────────────
    {
        "id":          "log_hidden",
        "name":        "Log Service Stopped",
        "label":       "log hidden",
        "type":        THRESHOLD,
        "enabled":     True,
        "description": "Logging service stopped on any endpoint — fires immediately.",
        "match": {
            "log_type": "system",
            "keywords": [
                "rsyslog stopped", "auditd stopped",
                "Windows Event Log stopped",
                "logging service disabled",
                "log service stopped",
                "audit service stopped",
            ],
        },
        "threshold": {
            "count":      1,
            "window_sec": 1,
            "group_by":   "host",
        },
        "alert": {
            "name":            "Log Service Stopped — Cover-Up Detected",
            "severity":        "CRITICAL",
            "description":     "Logging service stopped on {host} — activity now invisible",
            "mitre_tactic":    "TA0005",
            "mitre_technique": "T1070",
        },
        "soar": {
            "playbook":     "escalate_admin",
            "mode":         "AUTO",
            "target_field": "host",
        },
        "dedup": {
            "window_minutes": 10,
            "group_by": ["rule_id", "host"],
        },
    },
]

# ── Helpers ───────────────────────────────────────────────
def get_active_rules() -> list:
    return [r for r in RULES if r.get("enabled", True)]

def get_rule(rule_id: str) -> dict:
    return next((r for r in RULES if r["id"] == rule_id), {})

def get_rules_by_type(rule_type: str) -> list:
    return [r for r in RULES if r["type"] == rule_type]
