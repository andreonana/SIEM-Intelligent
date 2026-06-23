from flask import Flask, request, jsonify
from datetime import datetime
import threading

app = Flask(__name__)

logs_store = []
stats = {"total": 0, "errors": 0, "warnings": 0, "info": 0, "batches": 0}
lock = threading.Lock()

EXPECTED_API_KEY = "dev-key-temporaire"

def check_auth(req):
    return req.headers.get("X-API-Key", "") == EXPECTED_API_KEY

@app.route("/api/logs", methods=["POST"])
def receive_logs():
    if not check_auth(request):
        return jsonify({"error": "Unauthorized"}), 401

    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Invalid JSON"}), 400

    events = body.get("events", [])
    if not isinstance(events, list):
        return jsonify({"error": "events must be a list"}), 400

    received_at = datetime.utcnow().isoformat() + "Z"
    with lock:
        stats["batches"] += 1
        for ev in events:
            ev["_received_at"] = received_at
            sev = ev.get("severity", "INFO").upper()
            if sev == "ERROR":       stats["errors"]   += 1
            elif sev == "WARNING":   stats["warnings"] += 1
            else:                    stats["info"]     += 1
            stats["total"] += 1
            logs_store.append(ev)
            print(f"[LOG] {ev.get('severity','?')} | {ev.get('source_ip','?')} | {ev.get('raw_message','?')[:80]}")

    print(f"[BATCH] {len(events)} logs reçus | total={stats['total']}")
    return jsonify({"status": "ok", "received": len(events)}), 200

@app.route("/api/logs", methods=["GET"])
def get_logs():
    with lock:
        return jsonify({"stats": dict(stats), "logs": list(logs_store)}), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    print("Mock SIEM API démarrée sur http://0.0.0.0:8000")
    app.run(host="0.0.0.0", port=8000, debug=False)