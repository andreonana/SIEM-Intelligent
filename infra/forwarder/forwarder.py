import os, json, time, glob, requests, re

API_URL    = os.environ.get("API_URL", "http://host.docker.internal:8000/api/logs")
API_KEY    = os.environ.get("API_KEY", "dev-key-temporaire")
BATCH      = int(os.environ.get("BATCH_SIZE", "50"))
INTERVAL   = int(os.environ.get("POLL_INTERVAL", "5"))
OUTPUT_DIR = "/output"
STATE_FILE = "/state/offset.json"

# ---------------------------------------------------------------
# Détection simple du type et de la sévérité depuis le raw_message
# À enrichir quand le backend sera prêt
# ---------------------------------------------------------------
def detect_log_type(message: str) -> str:
    msg = message.lower()
    if "sshd" in msg or "ssh" in msg:
        return "ssh"
    if "sudo" in msg:
        return "sudo"
    if "nginx" in msg or "apache" in msg or "http" in msg:
        return "web"
    if "kernel" in msg or "oom" in msg:
        return "kernel"
    return "system"

def detect_severity(message: str) -> str:
    msg = message.lower()
    if any(w in msg for w in ["error", "fail", "critical", "emerg", "alert"]):
        return "ERROR"
    if any(w in msg for w in ["warn", "warning"]):
        return "WARNING"
    if any(w in msg for w in ["invalid", "refused", "denied", "attack", "brute"]):
        return "WARNING"
    return "INFO"

def detect_tags(message: str) -> list:
    msg = message.lower()
    tags = []
    if "failed password" in msg or "authentication failure" in msg:
        tags += ["ssh", "brute-force"]
    if "accepted password" in msg or "accepted publickey" in msg:
        tags += ["ssh", "login-success"]
    if "sudo" in msg:
        tags.append("sudo")
    if "connection refused" in msg:
        tags.append("connection-refused")
    if not tags:
        tags.append("generic")
    return tags

def extract_source_ip(message: str) -> str:
    """Extrait la première IP trouvée dans le message, sinon 'unknown'."""
    match = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', message)
    return match.group(1) if match else "unknown"

def build_event(raw: dict) -> dict:
    """Transforme un événement Filebeat brut en ton format JSON cible."""
    # Filebeat met le message dans le champ "message"
    raw_message = raw.get("message", json.dumps(raw))

    return {
        "timestamp":   raw.get("@timestamp",
                        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        "source_ip":   extract_source_ip(raw_message),
        "host":        raw.get("host", {}).get("name",
                        os.environ.get("HOSTNAME", "unknown"))
                       if isinstance(raw.get("host"), dict)
                       else raw.get("host", os.environ.get("HOSTNAME", "unknown")),
        "log_type":    detect_log_type(raw_message),
        "severity":    detect_severity(raw_message),
        "raw_message": raw_message,
        "tags":        detect_tags(raw_message),
    }

# ---------------------------------------------------------------
# Lecture / envoi (inchangé sauf appel à build_event)
# ---------------------------------------------------------------
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

def send_batch(events):
    payload = {
        "source": "filebeat-forwarder",
        "agent_version": "0.1.0",
        "events": events
    }
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
    }
    for attempt in range(5):
        try:
            r = requests.post(API_URL, json=payload, headers=headers,
                              timeout=10, verify=False)
            if r.status_code < 400:
                return True
            if r.status_code < 500:
                print(f"[WARN] API a rejeté le batch ({r.status_code}) — ignoré")
                return True
            print(f"[WARN] Erreur API {r.status_code}, retry {attempt+1}/5")
        except requests.exceptions.RequestException as e:
            print(f"[WARN] Réseau : {e}, retry {attempt+1}/5")
        time.sleep(2 ** attempt)
    print("[ERROR] Batch abandonné après 5 tentatives")
    return False

def tail_file(path, offset):
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
    print("[INFO] Forwarder démarré")
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