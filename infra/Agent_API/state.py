"""
Registre des IPs bloquées.

iptables/netsh ne sont pas pratiques à interroger pour "quelles IPs
sont bloquées par NOUS et pourquoi". On maintient donc un état applicatif
séparé, persisté en JSON, qui est la source de vérité pour /status.
Il reste synchronisé avec le pare-feu par construction : toute IP qui y
entre ou en sort passe par firewall.block_ip()/unblock_ip().
"""
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from . import config
except ImportError:  # pragma: no cover - fallback for direct execution
    import config

_lock = threading.Lock()
_STATE_FILE = config.LOG_DIR / "blocked_state.json"


def _load() -> dict:
    if not _STATE_FILE.exists():
        return {}
    try:
        return json.loads(_STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def is_blocked(ip: str) -> bool:
    with _lock:
        return ip in _load()


def add_blocked(ip: str, incident_id: str, rule_id: Optional[str], reason: str) -> None:
    with _lock:
        data = _load()
        data[ip] = {
            "blocked_at": datetime.now(timezone.utc).isoformat(),
            "incident_id": incident_id,
            "rule_id": rule_id,
            "reason": reason,
        }
        _save(data)


def remove_blocked(ip: str) -> bool:
    with _lock:
        data = _load()
        if ip in data:
            del data[ip]
            _save(data)
            return True
        return False


def list_blocked() -> dict:
    with _lock:
        return _load()
