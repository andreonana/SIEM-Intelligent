# ============================================================
# rules.py — The 5 Correlation Rules
# Each rule tells the engine what to look for and when to fire
# Used by: engine.py loads these on startup
# ============================================================

from app.modules.correlation.mitre import BANNED_IPS, WORK_HOURS

THRESHOLD  = "threshold"
SEQUENTIAL = "sequential"
TIME_BASED = "time_based"
LIST_MATCH = "list_match"

RULES = [

    # ── Rule 1 — Brute Force ──────────────────────────────
    {
        "id":          "brute_force",
        "name":        "Brute Force Attack",
        "label":       "brute force",
        "type":        THRESHOLD,
        "enabled":     True,
        "description": (
            "5 or more failed login attempts from the same "
            "source IP within 60 seconds."
        ),
        "match": {
            "log_type":  "auth",
            "keywords":  ["Failed password", "Invalid user",
                          "Authentication failure", "Failed login"],
        },
        "threshold": {
            "count":      5,
            "window_sec": 60,
            "group_by":   "source_ip",
        },
        "alert": {
            "name":             "Brute Force Attack Detected",
            "severity":         "CRITICAL",
            "description":      "{count} failed login attempts from {source_ip} in {elapsed}s",
            "mitre_tactic":     "TA0001",
            "mitre_technique":  "T1110",
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
        "description": (
            "A successful login outside 07:00-20:00 Monday-Friday. "
            "Weekend logins always trigger this rule."
        ),
        "match": {
            "log_type":  "auth",
            "keywords":  ["Accepted password", "session opened",
                          "logged in", "authentication success"],
        },
        "time_check": {
            "work_start":    WORK_HOURS["start"],   # 7
            "work_end":      WORK_HOURS["end"],     # 20
            "work_days":     WORK_HOURS["days"],    # Mon-Fri
            "group_by":      "username",
            # Accounts that are allowed to connect at any time
            "whitelist_env": "OUTSIDE_HOURS_WHITELIST",
        },
        "alert": {
            "name":            "Off-Hours Login Detected",
            "severity":        "WARNING",
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

    # ── Rule 3 — Internal Port Scan ───────────────────────
    {
        "id":          "port_scan",
        "name":        "Internal Port Scan",
        "label":       "port scan",
        "type":        THRESHOLD,
        "enabled":     True,
        "description": (
            "An internal machine contacts more than 15 different "
            "ports on other internal machines within 30 seconds. "
            "Sign of a compromised machine doing reconnaissance."
        ),
        "match": {
            "log_type":         "network",
            "source_type":      "internal",   # 192.168.x or 10.x
            "destination_type": "internal",
            "keywords":         ["port scan", "Nmap", "SYN scan",
                                 "connect scan"],
        },
        "threshold": {
            "count":      15,        # 15 different ports
            "window_sec": 30,
            "group_by":   "source_ip",
            "count_field": "destination_port",  # count unique ports
            # Whitelisted IPs — IT admin machines allowed to scan
            "whitelist_env": "SCAN_WHITELIST_IPS",
        },
        "alert": {
            "name":            "Internal Port Scan Detected",
            "severity":        "HIGH",
            "description":     "Internal machine {source_ip} scanned {count} ports in {elapsed}s",
            "mitre_tactic":    "TA0007",
            "mitre_technique": "T1046",
        },
        "soar": [
            {"playbook": "isolate_machine",  "mode": "AUTO", "target_field": "source_ip"},
            {"playbook": "escalate_admin",   "mode": "AUTO", "target_field": "source_ip"},
        ],
        "dedup": {
            "window_minutes": 10,
            "group_by": ["rule_id", "source_ip"],
        },
    },

    # ── Rule 4 — Banned IP Communication ─────────────────
    {
        "id":          "communication_banned",
        "name":        "Communication with Malicious IP",
        "label":       "communication banned",
        "type":        LIST_MATCH,
        "enabled":     True,
        "description": (
            "Any internal machine communicates with an IP address "
            "on the banned list. One occurrence is enough. "
            "Indicates malware infection or C2 communication."
        ),
        "match": {
            "log_type":    "network",
            "direction":   "outbound",
        },
        "list_check": {
            "field":      "destination_ip",
            "list":       BANNED_IPS,
            "group_by":   "source_ip",
            # One match is enough to trigger
            "threshold":  1,
        },
        "alert": {
            "name":            "Communication with Banned Malicious IP",
            "severity":        "CRITICAL",
            "description":     "{source_ip} contacted banned IP {destination_ip} — possible malware C2",
            "mitre_tactic":    "TA0011",
            "mitre_technique": "T1071",
        },
        "soar": [
            {"playbook": "block_ip",        "mode": "AUTO", "target_field": "destination_ip"},
            {"playbook": "isolate_machine",  "mode": "AUTO", "target_field": "source_ip"},
            {"playbook": "escalate_admin",   "mode": "AUTO", "target_field": "source_ip"},
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
        "description": (
            "The logging or audit service has been stopped on "
            "an endpoint. One occurrence triggers immediately. "
            "Sign of an attacker hiding their activity."
        ),
        "match": {
            "log_type": "system",
            "keywords": [
                "rsyslog stopped",
                "auditd stopped",
                "Windows Event Log stopped",
                "logging service disabled",
                "log service stopped",
                "audit service stopped",
            ],
        },
        "threshold": {
            "count":      1,   # one event is enough
            "window_sec": 1,
            "group_by":   "host",
        },
        "alert": {
            "name":            "Log Service Stopped — Possible Cover-Up",
            "severity":        "HIGH",
            "description":     "Logging service stopped on {host} — all subsequent activity invisible",
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

# ── Helper functions ──────────────────────────────────────
def get_active_rules() -> list:
    """Returns only enabled rules. Called by engine.py on startup."""
    return [r for r in RULES if r.get("enabled", True)]

def get_rule(rule_id: str) -> dict:
    """Returns one rule by ID."""
    return next((r for r in RULES if r["id"] == rule_id), {})

def get_rules_by_type(rule_type: str) -> list:
    """Returns all rules of a given type."""
    return [r for r in RULES if r["type"] == rule_type]
