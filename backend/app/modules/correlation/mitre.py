# ============================================================
# mitre.py — MITRE ATT&CK Lookup Table
# Maps each correlation rule to its MITRE tactic and technique
# Used by: service.py enriches every alert before indexing
# ============================================================

# Each key = the rule's name (matches CorrelationRule.name property)
# Each value = the MITRE data to attach to the alert

MITRE_MAP = {

    "bruteforce_threshold": {
        "tactic_id":    "TA0001",
        "tactic_name":  "Initial Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "description": (
            "Adversary tries many passwords rapidly against one "
            "account until one succeeds."
        ),
    },

    "business_hours_violation": {
        "tactic_id":    "TA0001",
        "tactic_name":  "Initial Access",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts — Off-Hours Access",
        "description": (
            "A valid account is used outside normal working hours "
            "— sign of compromise or insider threat."
        ),
    },

    "communication_banned": {
        "tactic_id":    "TA0011",
        "tactic_name":  "Command and Control",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "description": (
            "A machine contacts a known malicious IP — "
            "possible malware C2 communication."
        ),
    },

    "unauthorized_privileges": {
        "tactic_id":    "TA0004",
        "tactic_name":  "Privilege Escalation",
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "description": (
            "Privilege change made by an unapproved account — "
            "possible privilege escalation."
        ),
    },

    "log_hidden": {
        "tactic_id":    "TA0005",
        "tactic_name":  "Defense Evasion",
        "technique_id": "T1070",
        "technique_name": "Indicator Removal",
        "description": (
            "Logging service stopped — attacker hiding activity."
        ),
    },
}

# ── Banned IPs for communication_banned rule ──────────────
BANNED_IPS = [
    "94.12.44.17",
    "185.220.101.45",
    "178.43.12.87",
    "91.108.4.0",
    "45.142.212.100",
    "104.21.44.200",
    "193.32.161.12",
]

# ── Working hours for business_hours rule ─────────────────
WORK_HOURS = {
    "start": 7,
    "end":   20,
    "days":  [0, 1, 2, 3, 4],
}

# ── Helper ────────────────────────────────────────────────
def get_mitre(rule_name: str) -> dict:
    """
    Returns MITRE data for a given rule name.
    Returns empty dict if rule has no MITRE mapping.

    Usage in service.py:
        mitre = get_mitre(alert.rule_name)
        document["mitre_tactic"]    = mitre.get("tactic_id", "")
        document["mitre_technique"] = mitre.get("technique_id", "")
    """
    return MITRE_MAP.get(rule_name, {})
