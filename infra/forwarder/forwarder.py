import os, json, time, glob, requests, re
from datetime import datetime, timezone

# ── Config ───────────────────────────────────────────────────────────────────
API_URL    = os.environ.get("API_URL",      "http://mock-api:8000/api/logs")
API_KEY    = os.environ.get("API_KEY",      "dev-key-temporaire")
BATCH      = int(os.environ.get("BATCH_SIZE",    "50"))
INTERVAL   = int(os.environ.get("POLL_INTERVAL", "5"))
OUTPUT_DIR = "/output"
STATE_FILE = "/state/offset.json"

# ── Patterns de détection ────────────────────────────────────────────────────

# Syslog Linux standard : "Jan 15 10:00:01 hostname process[pid]: message"
RE_SYSLOG = re.compile(
    r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})'
    r'\s+(?P<host>\S+)\s+(?P<proc>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.+)$'
)

# Syslog avec année (RFC 3164 étendu) : "2024-01-15T10:00:01Z hostname process: message"
RE_SYSLOG_ISO = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+'
    r'(?P<host>\S+)\s+(?P<proc>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.+)$'
)

# Windows Event Log texte brut (export txt)
RE_WINLOG = re.compile(
    r'(?i)(?:Event ID|EventID)[:\s]+(?P<evtid>\d+)'
)

# Cisco IOS / routeur : "%FACILITY-SEVERITY-MNEMONIC: message"
RE_CISCO = re.compile(
    r'%(?P<facility>[A-Z0-9_]+)-(?P<sev>\d)-(?P<mnem>[A-Z0-9_]+):\s*(?P<msg>.+)$'
)

# Fortinet / iptables / pare-feu générique
RE_FIREWALL = re.compile(
    r'(?i)(?:action|disposition)=(?P<action>\w+)'
)

# IP dans n'importe quel message
RE_IP = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')

# Timestamp ISO dans un message
RE_ISO_TS = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?')

# ── Tables de correspondance ─────────────────────────────────────────────────

CISCO_SEV_MAP = {
    "0": "ERROR", "1": "ERROR", "2": "ERROR",
    "3": "ERROR", "4": "WARNING",
    "5": "INFO",  "6": "INFO",  "7": "INFO"
}

# Event IDs Windows → (log_type, severity, tags)
WINDOWS_EVENTID_MAP = {
    "4624": ("authentication", "INFO",    ["windows", "login-success"]),
    "4625": ("authentication", "WARNING", ["windows", "login-failed"]),
    "4634": ("authentication", "INFO",    ["windows", "logout"]),
    "4648": ("authentication", "WARNING", ["windows", "explicit-logon"]),
    "4719": ("policy",         "ERROR",   ["windows", "policy-change"]),
    "4720": ("user-mgmt",      "WARNING", ["windows", "account-created"]),
    "4726": ("user-mgmt",      "WARNING", ["windows", "account-deleted"]),
    "4728": ("user-mgmt",      "WARNING", ["windows", "group-change"]),
    "4732": ("user-mgmt",      "WARNING", ["windows", "group-change"]),
    "4740": ("authentication", "ERROR",   ["windows", "account-locked"]),
    "4756": ("user-mgmt",      "WARNING", ["windows", "group-change"]),
    "4771": ("authentication", "WARNING", ["windows", "kerberos-failed"]),
    "4776": ("authentication", "WARNING", ["windows", "ntlm-failed"]),
    "7045": ("system",         "WARNING", ["windows", "service-installed"]),
    "1102": ("audit",          "ERROR",   ["windows", "log-cleared"]),
    "4698": ("scheduler",      "WARNING", ["windows", "task-created"]),
    "4702": ("scheduler",      "WARNING", ["windows", "task-modified"]),
}

LINUX_PROC_MAP = {
    "sshd":          "ssh",
    "sudo":          "sudo",
    "su":            "sudo",
    "nginx":         "web",
    "apache2":       "web",
    "httpd":         "web",
    "kernel":        "kernel",
    "systemd":       "system",
    "cron":          "cron",
    "postfix":       "mail",
    "sendmail":      "mail",
    "named":         "dns",
    "dnsmasq":       "dns",
    "firewalld":     "firewall",
    "ufw":           "firewall",
    "iptables":      "firewall",
    "auditd":        "audit",
    "pam_unix":      "authentication",
    "login":         "authentication",
    "gdm":           "authentication",
    "smbd":          "smb",
    "nmbd":          "smb",
    "dockerd":       "container",
    "containerd":    "container",
}

CISCO_FACILITY_MAP = {
    "SEC":      "firewall",
    "FW":       "firewall",
    "ACL":      "firewall",
    "IDS":      "ids",
    "SYS":      "system",
    "LINK":     "network",
    "OSPF":     "routing",
    "BGP":      "routing",
    "EIGRP":    "routing",
    "SSH":      "ssh",
    "AAA":      "authentication",
    "DHCP":     "dhcp",
    "DNS":      "dns",
    "NTP":      "ntp",
    "CRYPTO":   "vpn",
    "IPSEC":    "vpn",
    "VPN":      "vpn",
}

# ── Détection du type de source ───────────────────────────────────────────────

def detect_source_type(raw_message: str, filebeat_fields: dict) -> str:
    """
    Retourne : 'linux_syslog' | 'windows_event' | 'cisco_ios' |
               'fortinet' | 'palo_alto' | 'checkpoint' | 'generic'
    """
    msg = raw_message.strip()

    # Windows Event Log (format texte ou JSON Filebeat winlog)
    if filebeat_fields.get("winlog") or filebeat_fields.get("event", {}).get("provider"):
        return "windows_event"
    if re.search(r'(?i)(EventID|Event ID|Log Name:\s*(Security|System|Application))', msg):
        return "windows_event"

    # Cisco IOS / NX-OS / ASA
    if re.search(r'%[A-Z0-9_]+-\d-[A-Z0-9_]+:', msg):
        return "cisco_ios"

    # Fortinet FortiGate
    if re.search(r'(?i)devname=\S+.*logid=\d+', msg):
        return "fortinet"

    # Palo Alto
    if re.search(r'(?i)THREAT|TRAFFIC|CONFIG.*panorama|panos', msg):
        return "palo_alto"

    # Check Point
    if re.search(r'(?i)product=\S+.*action=\S+.*src=', msg):
        return "checkpoint"

    # Syslog Linux (format standard)
    if RE_SYSLOG.match(msg) or RE_SYSLOG_ISO.match(msg):
        return "linux_syslog"

    return "generic"

# ── Parsers par type de source ────────────────────────────────────────────────

def parse_linux_syslog(raw: str, filebeat: dict) -> dict:
    m = RE_SYSLOG.match(raw.strip())
    if not m:
        m = RE_SYSLOG_ISO.match(raw.strip())
        if not m:
            return _generic(raw, filebeat, "linux_syslog")

    proc  = m.group("proc").strip().lower().split("/")[-1]
    msg   = m.group("msg")
    host  = m.group("host")
    log_type = LINUX_PROC_MAP.get(proc, "system")

    severity = _linux_severity(msg)
    tags     = _linux_tags(proc, msg)
    source_ip = _first_ip(msg)

    return {
        "timestamp":   _ts_from_filebeat(filebeat),
        "source_ip":   source_ip,
        "host":        host,
        "log_type":    log_type,
        "severity":    severity,
        "raw_message": raw,
        "tags":        tags,
        "os":          "linux",
        "process":     proc,
    }

def parse_windows_event(raw: str, filebeat: dict) -> dict:
    winlog = filebeat.get("winlog", {})
    event  = filebeat.get("event", {})

    # Depuis Filebeat winlog input (format riche)
    if winlog:
        evt_id   = str(winlog.get("event_id", ""))
        provider = winlog.get("provider_name", "unknown")
        computer = winlog.get("computer_name",
                   filebeat.get("host", {}).get("name", "unknown"))
        evt_data = winlog.get("event_data", {})
        src_ip   = (evt_data.get("IpAddress") or
                    evt_data.get("SourceAddress") or
                    evt_data.get("ClientAddress") or
                    _first_ip(raw))
    else:
        # Format texte brut exporté
        evt_id_m = RE_WINLOG.search(raw)
        evt_id   = evt_id_m.group("evtid") if evt_id_m else "0"
        provider = "Windows"
        computer = filebeat.get("host", {}).get("name", "unknown")
        src_ip   = _first_ip(raw)

    log_type, severity, tags = WINDOWS_EVENTID_MAP.get(
        evt_id,
        ("system", _generic_severity(raw), ["windows"])
    )

    return {
        "timestamp":   _ts_from_filebeat(filebeat),
        "source_ip":   src_ip or "unknown",
        "host":        computer,
        "log_type":    log_type,
        "severity":    severity,
        "raw_message": raw,
        "tags":        tags,
        "os":          "windows",
        "event_id":    evt_id,
        "provider":    provider,
    }

def parse_cisco_ios(raw: str, filebeat: dict) -> dict:
    m = RE_CISCO.search(raw)
    if not m:
        return _generic(raw, filebeat, "cisco_ios")

    facility = m.group("facility").split("_")[0]
    sev_num  = m.group("sev")
    mnem     = m.group("mnem")
    msg      = m.group("msg")

    log_type  = CISCO_FACILITY_MAP.get(facility, "network")
    severity  = CISCO_SEV_MAP.get(sev_num, "INFO")
    source_ip = _first_ip(raw)
    tags      = ["cisco", mnem.lower()]
    if log_type == "firewall":
        tags.append("firewall")
    if "deny" in msg.lower() or "block" in msg.lower():
        tags.append("blocked")
        severity = max_sev(severity, "WARNING")

    return {
        "timestamp":   _ts_from_filebeat(filebeat),
        "source_ip":   source_ip or "unknown",
        "host":        filebeat.get("host", {}).get("name", "cisco-device"),
        "log_type":    log_type,
        "severity":    severity,
        "raw_message": raw,
        "tags":        tags,
        "os":          "cisco_ios",
        "facility":    m.group("facility"),
        "mnemonic":    mnem,
    }

def parse_fortinet(raw: str, filebeat: dict) -> dict:
    fields = dict(re.findall(r'(\w+)="?([^"\s]+)"?', raw))

    action  = fields.get("action", fields.get("disposition", "unknown")).lower()
    src_ip  = fields.get("srcip",  fields.get("src", _first_ip(raw) or "unknown"))
    dst_ip  = fields.get("dstip",  fields.get("dst", "unknown"))
    subtype = fields.get("subtype", fields.get("type", "firewall")).lower()
    logid   = fields.get("logid", "")
    devname = fields.get("devname", filebeat.get("host", {}).get("name", "fortigate"))

    severity = "INFO"
    if action in ("deny", "block", "drop"):
        severity = "WARNING"
    elif action in ("alert", "critical"):
        severity = "ERROR"

    tags = ["fortinet", "firewall", subtype]
    if action in ("deny", "block", "drop"):
        tags.append("blocked")

    return {
        "timestamp":   _ts_from_filebeat(filebeat),
        "source_ip":   src_ip,
        "host":        devname,
        "log_type":    "firewall",
        "severity":    severity,
        "raw_message": raw,
        "tags":        tags,
        "os":          "fortios",
        "action":      action,
        "dst_ip":      dst_ip,
        "log_id":      logid,
    }

def parse_palo_alto(raw: str, filebeat: dict) -> dict:
    parts = raw.split(",")
    # Format CSV PAN-OS : champ 3=type, 6=src, 7=dst
    try:
        log_type_raw = parts[3].strip().lower() if len(parts) > 3 else "traffic"
        src_ip  = parts[6].strip()  if len(parts) > 6  else _first_ip(raw) or "unknown"
        action  = parts[29].strip().lower() if len(parts) > 29 else "unknown"
    except (IndexError, AttributeError):
        return _generic(raw, filebeat, "palo_alto")

    severity = "WARNING" if action in ("deny", "drop", "reset") else "INFO"
    tags = ["palo-alto", log_type_raw]
    if action in ("deny", "drop"):
        tags.append("blocked")

    return {
        "timestamp":   _ts_from_filebeat(filebeat),
        "source_ip":   src_ip,
        "host":        filebeat.get("host", {}).get("name", "palo-alto"),
        "log_type":    "firewall",
        "severity":    severity,
        "raw_message": raw,
        "tags":        tags,
        "os":          "panos",
        "action":      action,
    }

def parse_checkpoint(raw: str, filebeat: dict) -> dict:
    fields = dict(re.findall(r'(\w+)=(\S+)', raw))

    src_ip  = fields.get("src",    _first_ip(raw) or "unknown")
    action  = fields.get("action", "unknown").lower()
    product = fields.get("product", "firewall").lower()

    severity = "WARNING" if action in ("drop", "reject", "block") else "INFO"
    tags = ["checkpoint", "firewall"]
    if action in ("drop", "reject", "block"):
        tags.append("blocked")

    return {
        "timestamp":   _ts_from_filebeat(filebeat),
        "source_ip":   src_ip,
        "host":        fields.get("hostname", filebeat.get("host", {}).get("name", "checkpoint")),
        "log_type":    "firewall",
        "severity":    severity,
        "raw_message": raw,
        "tags":        tags,
        "os":          "gaia",
        "action":      action,
        "product":     product,
    }

def _generic(raw: str, filebeat: dict, source_type: str) -> dict:
    return {
        "timestamp":   _ts_from_filebeat(filebeat),
        "source_ip":   _first_ip(raw) or "unknown",
        "host":        filebeat.get("host", {}).get("name",
                       os.environ.get("HOSTNAME", "unknown"))
                       if isinstance(filebeat.get("host"), dict)
                       else filebeat.get("host", os.environ.get("HOSTNAME", "unknown")),
        "log_type":    "generic",
        "severity":    _generic_severity(raw),
        "raw_message": raw,
        "tags":        [source_type, "unclassified"],
        "os":          "unknown",
    }

# ── Fonction principale de normalisation ─────────────────────────────────────

def build_event(filebeat_raw: dict) -> dict:
    raw_message = filebeat_raw.get("message", json.dumps(filebeat_raw))
    source_type = detect_source_type(raw_message, filebeat_raw)

    parsers = {
        "linux_syslog":  parse_linux_syslog,
        "windows_event": parse_windows_event,
        "cisco_ios":     parse_cisco_ios,
        "fortinet":      parse_fortinet,
        "palo_alto":     parse_palo_alto,
        "checkpoint":    parse_checkpoint,
        "generic":       _generic,
    }

    event = parsers[source_type](raw_message, filebeat_raw)
    event["source_type"] = source_type  # champ bonus pour debug/routing backend
    return event

# ── Helpers ───────────────────────────────────────────────────────────────────

def _first_ip(text: str) -> str | None:
    m = RE_IP.search(text)
    return m.group(1) if m else None

def _ts_from_filebeat(fb: dict) -> str:
    return fb.get("@timestamp",
           time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

def max_sev(a: str, b: str) -> str:
    order = {"INFO": 0, "WARNING": 1, "ERROR": 2}
    return a if order.get(a, 0) >= order.get(b, 0) else b

def _linux_severity(msg: str) -> str:
    m = msg.lower()
    if any(w in m for w in ["error", "fail", "critical", "emerg", "alert", "fatal"]):
        return "ERROR"
    if any(w in m for w in ["warn", "warning", "invalid", "refused",
                              "denied", "attack", "brute", "blocked"]):
        return "WARNING"
    return "INFO"

def _generic_severity(msg: str) -> str:
    return _linux_severity(msg)

def _linux_tags(proc: str, msg: str) -> list:
    m = msg.lower()
    tags = [proc] if proc else []
    if "failed password" in m or "authentication failure" in m:
        tags += ["brute-force", "login-failed"]
    elif "accepted password" in m or "accepted publickey" in m:
        tags.append("login-success")
    if "invalid user" in m:
        tags.append("invalid-user")
    if "connection closed" in m or "disconnected" in m:
        tags.append("disconnection")
    if "sudo" in proc and "command not allowed" in m:
        tags.append("privilege-escalation")
    if "ufw block" in m or "iptables" in m:
        tags.append("firewall")
    if not tags:
        tags.append("generic")
    return list(dict.fromkeys(tags))  # déduplique en conservant l'ordre

# ── Pipeline envoi ────────────────────────────────────────────────────────────

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def send_batch(events: list) -> bool:
    payload = {"source": "filebeat-forwarder", "agent_version": "0.2.0", "events": events}
    headers = {"Content-Type": "application/json", "X-API-Key": API_KEY}
    for attempt in range(5):
        try:
            r = requests.post(API_URL, json=payload, headers=headers, timeout=10, verify=False)
            if r.status_code < 400:
                return True
            if r.status_code < 500:
                print(f"[WARN] API 4xx ({r.status_code}) — batch ignoré")
                return True
            print(f"[WARN] API {r.status_code} — retry {attempt+1}/5")
        except requests.exceptions.RequestException as e:
            print(f"[WARN] Réseau : {e} — retry {attempt+1}/5")
        time.sleep(2 ** attempt)
    print("[ERROR] Batch abandonné après 5 tentatives")
    return False

def tail_file(path: str, offset: int):
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(offset)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                raw = {"message": line}
            events.append(build_event(raw))
        new_offset = f.tell()
    return events, new_offset

def main():
    print("[INFO] Forwarder v0.2.0 démarré — support multi-OS/multi-équipement")
    state = load_state()
    while True:
        files = sorted(glob.glob(os.path.join(OUTPUT_DIR, "beats-output*")))
        for path in files:
            offset = state.get(path, 0)
            try:
                current_size = os.path.getsize(path)
            except FileNotFoundError:
                continue
            if offset > current_size:
                offset = 0
            if offset == current_size:
                continue
            events, new_offset = tail_file(path, offset)
            for i in range(0, len(events), BATCH):
                if send_batch(events[i:i+BATCH]):
                    state[path] = new_offset
                    save_state(state)
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()