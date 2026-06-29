# ============================================================
# mitre.py — MITRE ATT&CK Scenario Registry
# Defines the 5 attack scenarios the SIEM detects
# Reference: https://attack.mitre.org
# ============================================================

TACTICS = {
    "TA0001": "Initial Access",
    "TA0005": "Defense Evasion",
    "TA0007": "Discovery",
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
            "A valid account is used to log in at an unusual "
            "time — a sign of compromise or insider threat."
        ),
    },
    "T1046": {
        "name": "Network Service Discovery — Internal Port Scan",
        "tactic": "TA0007",
        "description": (
            "A compromised internal machine scans other internal "
            "machines to find open ports and services to target."
        ),
    },
    "T1071": {
        "name": "Application Layer Protocol — Banned IP Communication",
        "tactic": "TA0011",
        "description": (
            "A machine inside the network communicates with a known "
            "malicious IP address — a sign of malware infection "
            "or command and control activity."
        ),
    },
    "T1070": {
        "name": "Indicator Removal — Log Service Stopped",
        "tactic": "TA0005",
        "description": (
            "The attacker stops or disables the logging service "
            "to hide their tracks and prevent detection."
        ),
    },
}

# ── Banned IP list ────────────────────────────────────────
# Known malicious IPs your SIEM watches for
# In production: loaded from a threat intelligence feed
# For the demo: this static list is used
BANNED_IPS = [
    "94.12.44.17",    # known C2 server
    "185.220.101.45", # TOR exit node linked to attacks
    "178.43.12.87",   # attacker IP from CTU incident
    "91.108.4.0",     # malware distribution server
    "45.142.212.100", # ransomware C2
    "104.21.44.200",  # phishing infrastructure
    "193.32.161.12",  # known APT infrastructure
]

# ── Working hours definition ──────────────────────────────
WORK_HOURS = {
    "start": 7,   # 07:00
    "end":   20,  # 20:00
    "days":  [0, 1, 2, 3, 4],  # Monday=0 to Friday=4
    # Saturday=5 and Sunday=6 are always outside hours
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
            "An attacker tries many passwords rapidly against "
            "an account. Detected when 5 or more failed login "
            "attempts come from the same source IP within 60 seconds."
        ),
        "attack_steps": [
            "Attacker identifies a target account or service",
            "Attacker sends rapid repeated login attempts with different passwords",
            "Multiple failed authentication events are generated",
            "If undetected: attacker eventually finds the correct password",
            "Compromised account gives attacker access to the system",
        ],
        "log_indicators": [
            "log_type = 'auth'",
            "raw_message contains 'Failed' OR 'Invalid' OR 'Authentication failure'",
            "Same source_ip appears 5 or more times within 60 seconds",
        ],
        "soar_response": "block_ip (AUTO)",
        "false_positive_risk": (
            "A legitimate user who forgot their password. "
            "The 5-attempt threshold in 60 seconds reduces this risk "
            "as a real user rarely tries that many times that fast."
        ),
    },

    "outside_hours": {
        "name":           "Connection Outside Working Hours",
        "rule_id":        "outside_hours",
        "tactic_id":      "TA0001",
        "technique_id":   "T1078",
        "severity":       "WARNING",
        "description": (
            "A user account connects to the system outside normal "
            "working hours (before 07:00 or after 20:00, or on "
            "weekends). This can indicate account compromise or "
            "an insider threat acting covertly."
        ),
        "attack_steps": [
            "Attacker or insider waits until outside working hours",
            "Uses valid credentials to log in without being noticed",
            "Accesses sensitive files or systems while most staff are offline",
            "Exfiltrates data or plants backdoors under the cover of off-hours",
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
            "Known exceptions (maintenance windows, on-call staff) "
            "should be added to a whitelist in the .env file."
        ),
    },

    "port_scan": {
        "name":           "Internal Port Scan",
        "rule_id":        "port_scan",
        "tactic_id":      "TA0007",
        "technique_id":   "T1046",
        "severity":       "HIGH",
        "description": (
            "An internal machine is scanning other machines on the "
            "network looking for open ports. This is a sign that "
            "the machine is compromised and the attacker is doing "
            "internal reconnaissance before moving laterally."
        ),
        "attack_steps": [
            "Attacker has already compromised one internal machine",
            "Attacker runs a port scanner (nmap or similar) from that machine",
            "The machine sends connection probes to many ports on other machines",
            "Open ports are identified as targets for the next attack step",
            "Attacker moves to another machine using a discovered open service",
        ],
        "log_indicators": [
            "log_type = 'network'",
            "source_ip is an INTERNAL IP (192.168.x.x or 10.x.x.x)",
            "destination_ip is also INTERNAL",
            "More than 15 different destination ports contacted in 30 seconds",
            "OR raw_message contains 'port scan' OR 'Nmap'",
        ],
        "soar_response": "isolate_machine (AUTO) + escalate_admin (AUTO)",
        "false_positive_risk": (
            "A legitimate IT administrator running a vulnerability scan. "
            "Admin machines should be whitelisted in the .env file "
            "under SCAN_WHITELIST_IPS."
        ),
    },

    "communication_banned": {
        "name":           "Communication with Banned Malicious IP",
        "rule_id":        "communication_banned",
        "tactic_id":      "TA0011",
        "technique_id":   "T1071",
        "severity":       "CRITICAL",
        "description": (
            "A machine inside the CTU network is communicating "
            "with a known malicious IP address. This strongly "
            "indicates the machine is infected with malware "
            "that is contacting its command and control server."
        ),
        "attack_steps": [
            "Malware is installed on an internal machine (via phishing or exploit)",
            "Malware attempts to contact its C2 server to receive commands",
            "The outbound connection to the malicious IP is logged",
            "Attacker can now remotely control the infected machine",
            "Data theft, ransomware deployment, or lateral movement follows",
        ],
        "log_indicators": [
            "log_type = 'network'",
            "direction = 'outbound'",
            "destination_ip is in the BANNED_IPS list",
            "Single occurrence is enough to trigger CRITICAL alert",
        ],
        "soar_response": "block_ip (AUTO) + isolate_machine (AUTO) + escalate_admin (AUTO)",
        "false_positive_risk": (
            "Very low. Legitimate software does not contact known "
            "malicious IPs. Any match should be treated as a "
            "confirmed infection until proven otherwise."
        ),
    },

    "log_hidden": {
        "name":           "Log Service Stopped — Hiding Activity",
        "rule_id":        "log_hidden",
        "tactic_id":      "TA0005",
        "technique_id":   "T1070",
        "severity":       "HIGH",
        "description": (
            "The logging or audit service has been stopped on an "
            "endpoint. This is a deliberate attempt by an attacker "
            "to stop the SIEM from receiving logs from that machine, "
            "hiding all subsequent activity."
        ),
        "attack_steps": [
            "Attacker has access to a machine inside the network",
            "Attacker runs: systemctl stop rsyslog OR net stop eventlog",
            "The logging service sends a final 'stopped' event before going silent",
            "All subsequent activity on that machine becomes invisible to the SIEM",
            "Attacker can now act freely without generating any detectable logs",
        ],
        "log_indicators": [
            "log_type = 'system'",
            "raw_message contains 'rsyslog stopped' OR 'auditd stopped'",
            "OR raw_message contains 'Windows Event Log stopped'",
            "OR raw_message contains 'logging service disabled'",
            "Single occurrence on any host triggers immediate alert",
        ],
        "soar_response": "escalate_admin (AUTO) via webhook immediately",
        "false_positive_risk": (
            "Planned system maintenance that includes stopping log services. "
            "A maintenance window flag in the settings can suppress "
            "this alert during scheduled downtime."
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
    """
    Checks if an IP is in the banned list.
    Called by the correlation engine for every outbound connection.

    Usage:
        if is_banned_ip("94.12.44.17"):
            # trigger communication_banned rule
    """
    return ip in BANNED_IPS

def is_outside_hours(hour: int, weekday: int) -> bool:
    """
    Checks if a given hour and weekday is outside working hours.
    Called by the engine for every successful login event.

    Usage:
        from datetime import datetime
        now = datetime.utcnow()
        if is_outside_hours(now.hour, now.weekday()):
            # trigger outside_hours rule
    """
    if weekday not in WORK_HOURS["days"]:
        return True
    return hour < WORK_HOURS["start"] or hour >= WORK_HOURS["end"]
