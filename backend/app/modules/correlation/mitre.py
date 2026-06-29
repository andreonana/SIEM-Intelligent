# ============================================================
# mitre.py — MITRE ATT&CK Scenario Registry
# 5 attack scenarios the SIEM detects
# Reference: https://attack.mitre.org
# ============================================================

TACTICS = {
    "TA0001": "Initial Access",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
}

TECHNIQUES = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "TA0001",
        "description": (
            "Adversary tries many passwords rapidly against "
            "one account until one succeeds."
        ),
    },
    "T1078": {
        "name": "Valid Accounts — Off-Hours Access",
        "tactic": "TA0001",
        "description": (
            "A valid account is used outside normal working hours "
            "— a sign of compromise or insider threat."
        ),
    },
    "T1098": {
        "name": "Account Manipulation — Unauthorized Privilege",
        "tactic": "TA0004",
        "description": (
            "An account is granted elevated privileges "
            "without going through the normal approval process. "
            "Could indicate privilege escalation by an attacker."
        ),
    },
    "T1071": {
        "name": "Application Layer Protocol — Banned IP Communication",
        "tactic": "TA0011",
        "description": (
            "A machine inside the network communicates with a known "
            "malicious IP address — sign of malware or C2 activity."
        ),
    },
    "T1070": {
        "name": "Indicator Removal — Log Service Stopped",
        "tactic": "TA0005",
        "description": (
            "The attacker stops the logging service to hide "
            "their tracks and prevent detection."
        ),
    },
}

# ── Banned IP list ────────────────────────────────────────
BANNED_IPS = [
    "94.12.44.17",
    "185.220.101.45",
    "178.43.12.87",
    "91.108.4.0",
    "45.142.212.100",
    "104.21.44.200",
    "193.32.161.12",
]

# ── Working hours ─────────────────────────────────────────
WORK_HOURS = {
    "start": 7,
    "end":   20,
    "days":  [0, 1, 2, 3, 4],
}

# ── Attack scenarios ──────────────────────────────────────
SCENARIOS = {

    "brute_force": {
        "name":           "Brute Force Attack",
        "rule_id":        "brute_force",
        "tactic_id":      "TA0001",
        "technique_id":   "T1110",
        "severity":       "CRITICAL",
        "description": (
            "An attacker sends rapid repeated login attempts "
            "from the same IP. Detected when 5 or more failures "
            "occur within 60 seconds."
        ),
        "attack_steps": [
            "Attacker identifies a service accepting logins (SSH, RDP, web login)",
            "Automated tool sends thousands of password attempts per minute",
            "Each failure generates a warning auth log",
            "If undetected: attacker eventually finds the correct password",
            "Compromised account becomes attacker foothold inside the network",
        ],
        "log_indicators": [
            "log_type = 'auth'",
            "raw_message contains 'Failed' OR 'Invalid' OR 'Authentication failure'",
            "Same source_ip appears 5+ times within 60 seconds",
        ],
        "soar_response": "block_ip (AUTO)",
        "false_positive_risk": (
            "A legitimate user who forgot their password. "
            "The 5-attempt threshold in 60 seconds reduces this risk."
        ),
    },

    "outside_hours": {
        "name":           "Connection Outside Working Hours",
        "rule_id":        "outside_hours",
        "tactic_id":      "TA0001",
        "technique_id":   "T1078",
        "severity":       "CRITICAL",
        "description": (
            "A successful login outside 07:00-20:00 Monday-Friday "
            "or on weekends. Indicates account compromise or "
            "an insider threat acting covertly."
        ),
        "attack_steps": [
            "Attacker obtains valid credentials via phishing or brute force",
            "Waits until outside working hours to avoid detection",
            "Logs in using the stolen credentials",
            "Authentication success log generated at unusual time",
            "SIEM checks timestamp against working hours and fires CRITICAL alert",
        ],
        "log_indicators": [
            "log_type = 'auth'",
            "raw_message contains 'Accepted' OR 'session opened' OR 'logged in'",
            "timestamp.hour < 7 OR timestamp.hour >= 20",
            "OR timestamp.weekday in [5, 6] (Saturday or Sunday)",
        ],
        "soar_response": "escalate_admin (AUTO)",
        "false_positive_risk": (
            "A legitimate employee working late or on weekends. "
            "Known exceptions should be whitelisted in .env."
        ),
    },

    "unauthorized_privileges": {
        "name":           "Unauthorized Privilege Modification",
        "rule_id":        "unauthorized_privileges",
        "tactic_id":      "TA0004",
        "technique_id":   "T1098",
        "severity":       "CRITICAL",
        "description": (
            "A user account has been granted elevated privileges "
            "without going through the normal approval process. "
            "This may indicate privilege escalation by an attacker "
            "who has compromised an admin account."
        ),
        "attack_steps": [
            "Attacker has access to a privileged account",
            "Attacker modifies permissions of another account to gain persistence",
            "sudo or admin rights are added without an official request",
            "The privilege change is logged by the system",
            "SIEM detects the unrecognized privilege modification and fires CRITICAL",
        ],
        "log_indicators": [
            "log_type = 'auth' OR log_type = 'system'",
            "raw_message contains 'sudo' OR 'privilege' OR 'admin' OR 'root'",
            "AND raw_message contains 'added' OR 'granted' OR 'modified' OR 'changed'",
            "username performing the change is NOT in the approved admin list",
        ],
        "soar_response": "disable_account (CONFIRM) + escalate_admin (AUTO)",
        "false_positive_risk": (
            "A legitimate IT admin granting rights to a new employee. "
            "Approved admins should be listed in APPROVED_ADMINS in .env. "
            "Changes from approved admins do not trigger this rule."
        ),
    },

    "communication_banned": {
        "name":           "Communication with Malicious IP",
        "rule_id":        "communication_banned",
        "tactic_id":      "TA0011",
        "technique_id":   "T1071",
        "severity":       "WARNING",
        "description": (
            "A machine inside the network communicates with a "
            "known malicious IP. Indicates possible malware "
            "infection contacting a command and control server."
        ),
        "attack_steps": [
            "Malware installed via phishing or exploit",
            "Malware contacts C2 server to receive attacker commands",
            "Outbound connection to malicious IP appears in network logs",
            "SIEM checks every outbound IP against the banned list",
            "Match found — WARNING alert triggered",
        ],
        "log_indicators": [
            "log_type = 'network'",
            "direction = 'outbound'",
            "destination_ip is in BANNED_IPS list",
            "Single occurrence is enough",
        ],
        "soar_response": "block_ip (AUTO) + escalate_admin (AUTO)",
        "false_positive_risk": (
            "Very low. Legitimate software does not contact known "
            "malicious IPs. Any match should be investigated."
        ),
    },

    "log_hidden": {
        "name":           "Log Service Stopped — Hiding Activity",
        "rule_id":        "log_hidden",
        "tactic_id":      "TA0005",
        "technique_id":   "T1070",
        "severity":       "CRITICAL",
        "description": (
            "The logging service has been deliberately stopped on "
            "an endpoint. The attacker is trying to prevent the SIEM "
            "from receiving any further logs from that machine."
        ),
        "attack_steps": [
            "Attacker has access to a machine inside the network",
            "Runs: systemctl stop rsyslog OR net stop eventlog",
            "Logging service sends final 'stopped' event before silence",
            "SIEM detects this final event and fires CRITICAL immediately",
            "All subsequent attacker activity on that machine is invisible",
        ],
        "log_indicators": [
            "log_type = 'system'",
            "raw_message contains 'rsyslog stopped' OR 'auditd stopped'",
            "OR 'Windows Event Log stopped' OR 'logging service disabled'",
            "Single occurrence on any host triggers CRITICAL immediately",
        ],
        "soar_response": "escalate_admin (AUTO)",
        "false_positive_risk": (
            "Planned maintenance. Set MAINTENANCE_MODE=true in .env "
            "to suppress alerts during scheduled downtime."
        ),
    },
}

# ── Helper functions ──────────────────────────────────────
def get_scenario(scenario_id: str) -> dict:
    return SCENARIOS.get(scenario_id, {})

def get_technique(technique_id: str) -> dict:
    return TECHNIQUES.get(technique_id, {})

def get_tactic_name(tactic_id: str) -> str:
    return TACTICS.get(tactic_id, "Unknown Tactic")

def list_scenarios() -> list:
    return [
        {
            "id":           sid,
            "name":         s["name"],
            "tactic_id":    s["tactic_id"],
            "technique_id": s["technique_id"],
            "severity":     s["severity"],
            "rule_id":      s["rule_id"],
            "soar":         s["soar_response"],
        }
        for sid, s in SCENARIOS.items()
    ]

def is_banned_ip(ip: str) -> bool:
    return ip in BANNED_IPS

def is_outside_hours(hour: int, weekday: int) -> bool:
    if weekday not in WORK_HOURS["days"]:
        return True
    return hour < WORK_HOURS["start"] or hour >= WORK_HOURS["end"]
