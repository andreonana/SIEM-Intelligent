"""
Configuration de l'AgentAPI.

Toutes les valeurs sensibles (token, IPs autorisées) doivent venir de
variables d'environnement

ce module regroupe toutes les constates de configuration dont l'agentAPI à besoin 
et qui sont présent dans le .env, afin de tout centraliser

"""
import os
import ipaddress
from pathlib import Path

from dotenv import load_dotenv

# Charge le fichier .env à la racine du projet si présent.
ROOT_DIR = Path(__file__).resolve().parents[2]
load_dotenv(ROOT_DIR / ".env")


def _env(key: str, default: str = "") -> str:
    value = os.environ.get(key, default)
    return value.strip() if isinstance(value, str) else default


def _env_int(key: str, default: int) -> int:
    value = _env(key, "")
    if not value:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(f"{key} doit etre un entier valide") from exc


def _validate_ip_set(name: str, values: set[str]) -> None:
    for value in values:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise RuntimeError(f"{name} contient une adresse IP invalide: {value}") from exc


# --- Authentification ---
# Token partagé entre le SIEM backend et l'AgentAPI (header X-API-Key).
# Générer avec : python -c "import secrets; print(secrets.token_hex(32))"
API_TOKEN = _env("AGENTAPI_TOKEN", "")

# Liste blanche des IPs autorisées à appeler cette API (le SIEM backend).
# Format: "10.0.0.5,10.0.0.6"
_raw_allowed = _env("AGENTAPI_ALLOWED_CALLERS", "")
ALLOWED_CALLERS = {ip.strip() for ip in _raw_allowed.split(",") if ip.strip()}

# --- Comportement métier ---
# Délai (secondes) avant exécution effective d'une action en mode CONFIRM.
CONFIRM_DELAY_SECONDS = _env_int("AGENTAPI_CONFIRM_DELAY", 60)

# IPs qu'on ne bloquera jamais, quoi qu'il arrive (garde-fou anti auto-DOS).
# Aucune dépendance à un boîtier réseau centralisé (pas de pfSense) : ce sont
# juste des IPs propres à CETTE machine, à ne jamais bloquer par erreur :
# - loopback (127.0.0.1, ::1)
# - la passerelle par défaut DE CETTE machine (son routeur local, ex: 192.168.1.1)
#   -> un faux positif qui bloquerait cette IP couperait la machine du réseau
#      entier, y compris l'accès du SIEM pour la débloquer
# - l'IP du SIEM backend lui-même (sinon plus aucun ordre /block ni /unblock
#   ne peut arriver jusqu'ici)
_raw_never_block = _env("AGENTAPI_NEVER_BLOCK", "127.0.0.1,::1")
NEVER_BLOCK = {ip.strip() for ip in _raw_never_block.split(",") if ip.strip()}

# --- Journalisation ---
# -- repertoire où seront stockés les logs d'audit et de debug de l'API ---
LOG_DIR = Path(_env("AGENTAPI_LOG_DIR", str(Path(__file__).resolve().parent / "logs_audi")))
AUDIT_LOG_FILE = LOG_DIR / "audit.jsonl"

# --- Réseau ---
LISTEN_HOST = _env("AGENTAPI_HOST", "0.0.0.0")
LISTEN_PORT = _env_int("AGENTAPI_PORT", 9000)

# --- Nom de la chaîne iptables dédiée (Linux) ---
# Une chaîne séparée permet de lister/purger uniquement nos règles
# sans toucher au reste de la configuration pare-feu de la machine.
IPTABLES_CHAIN = "AGENTAPI_BLOCK"

# --- Nom du groupe de règles netsh (Windows) ---
NETSH_RULE_PREFIX = "AgentAPI_Block_"


def validate_config() -> None:
    """Vérifie que la config minimale est présente au démarrage. Fail-fast."""
    if not API_TOKEN:
        raise RuntimeError(
            "AGENTAPI_TOKEN n'est pas défini. "
            "L'API ne doit jamais démarrer sans authentification."
        )
    if not ALLOWED_CALLERS:
        raise RuntimeError(
            "AGENTAPI_ALLOWED_CALLERS n'est pas défini. "
            "Définir au moins l'IP du SIEM backend autorisé à appeler cette API."
        )
    _validate_ip_set("AGENTAPI_ALLOWED_CALLERS", ALLOWED_CALLERS)
    _validate_ip_set("AGENTAPI_NEVER_BLOCK", NEVER_BLOCK)
