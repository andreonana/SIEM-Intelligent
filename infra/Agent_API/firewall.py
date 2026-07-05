"""
Couche d'exécution pare-feu.
Il est là pour bloquer ou débloquer les IPS des machines qui tentent de se 
connecter à l'agentAPI, selon les ordres reçus du SIEM. 

Règles de sécurité non négociables ici :
- JAMAIS `subprocess.run(..., shell=True)` avec une IP interpolée dans une
  chaîne : c'est une injection de commande ouverte. On passe toujours une
  liste d'arguments, et l'IP a déjà été validée par `ipaddress` en amont
  (models.py) avant d'arriver jusqu'ici.
- Chaque opération est idempotente : bloquer une IP déjà bloquée ne doit
  pas empiler des règles en double, débloquer 1bbbune IP absente ne doit pas
  planter.
- Toutes les règles créées par cette API vivent dans une chaîne/groupe
  dédié, pour pouvoir les lister et les purger sans toucher au reste de
  la configuration pare-feu de la machine.
"""
import platform
import subprocess
from ipaddress import IPv4Address, ip_address

try:
    from . import config
except ImportError:  # pragma: no cover - fallback for direct execution
    import config


class FirewallError(Exception):
    pass


UNBLOCKABLE_IPV4_VALUES = {
    IPv4Address("0.0.0.0"),
    IPv4Address("255.255.255.255"),
}


def _normalize_ip(ip: str) -> str:
    try:
        parsed = ip_address(ip)
    except ValueError as exc:
        raise FirewallError(f"Adresse IP invalide: {ip}") from exc

    if parsed.version != 4:
        raise FirewallError("IPv6 n'est pas encore supporte par l'agent firewall actuel.")

    return str(parsed)


def _is_protected_ip(ip: str) -> bool:
    parsed = ip_address(ip)
    return (
        parsed in UNBLOCKABLE_IPV4_VALUES
        or parsed.is_loopback
        or parsed.is_multicast
        or parsed.is_unspecified
        or parsed.is_link_local
        or parsed.is_reserved
        or ip in config.NEVER_BLOCK
        or ip in config.ALLOWED_CALLERS
    )


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise FirewallError(f"Commande échouée: {' '.join(cmd)} -- stderr: {exc.stderr}") from exc
    except subprocess.TimeoutExpired as exc:
        raise FirewallError(f"Timeout sur commande: {' '.join(cmd)}") from exc
    except FileNotFoundError as exc:
        raise FirewallError(f"Binaire introuvable: {cmd[0]}") from exc


def get_os() -> str:
    system = platform.system().lower()
    if system not in ("linux", "windows"):
        raise FirewallError(f"OS non supporté par l'AgentAPI: {system}")
    return system


# --- gestion des rêgles iptables pour linux ---

def _safe_check(cmd: list[str]) -> subprocess.CompletedProcess:
    """Comme subprocess.run, mais transforme toute absence de binaire/timeout
    en FirewallError au lieu de laisser fuiter une exception non gérée."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except FileNotFoundError as exc:
        raise FirewallError(f"Binaire introuvable: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise FirewallError(f"Timeout sur commande: {' '.join(cmd)}") from exc


def _ensure_chain_linux() -> None:
    """Crée la chaîne dédiée si absente et s'assure qu'elle est bien
    branchée sur INPUT/FORWARD. Idempotent : ignore l'erreur si elle existe déjà."""
    chain = config.IPTABLES_CHAIN
    _safe_check(["iptables", "-N", chain])
    # Vérifie si le jump existe déjà dans INPUT avant de l'ajouter (évite les doublons).
    check = _safe_check(["iptables", "-C", "INPUT", "-j", chain])
    if check.returncode != 0:
        _run(["iptables", "-I", "INPUT", "-j", chain])


def _is_blocked_linux(ip: str) -> bool:
    check = _safe_check(["iptables", "-C", config.IPTABLES_CHAIN, "-s", ip, "-j", "DROP"])
    return check.returncode == 0


def _block_linux(ip: str) -> None:
    _ensure_chain_linux()
    if _is_blocked_linux(ip):
        return  # idempotent : déjà bloquée
    _run(["iptables", "-A", config.IPTABLES_CHAIN, "-s", ip, "-j", "DROP"])


def _unblock_linux(ip: str) -> None:
    if not _is_blocked_linux(ip):
        return  # idempotent : rien à faire
    _run(["iptables", "-D", config.IPTABLES_CHAIN, "-s", ip, "-j", "DROP"])


# --- Windows (netsh advfirewall) ---

def _rule_name(ip: str) -> str:
    return f"{config.NETSH_RULE_PREFIX}{ip}"


def _is_blocked_windows(ip: str) -> bool:
    result = _safe_check(["netsh", "advfirewall", "firewall", "show", "rule", f"name={_rule_name(ip)}"])
    return "No rules match" not in result.stdout and result.returncode == 0


def _block_windows(ip: str) -> None:
    if _is_blocked_windows(ip):
        return
    _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={_rule_name(ip)}",
        "dir=in", "action=block", f"remoteip={ip}",
    ])
    _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={_rule_name(ip)}_out",
        "dir=out", "action=block", f"remoteip={ip}",
    ])


def _unblock_windows(ip: str) -> None:
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={_rule_name(ip)}"],
        capture_output=True, text=True,
    )
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={_rule_name(ip)}_out"],
        capture_output=True, text=True,
    )


# --- API publique du module ---

def block_ip(ip: str) -> None:
    ip = _normalize_ip(ip)
    if _is_protected_ip(ip):
        raise FirewallError(f"'{ip}' est protegee/non bloquable, refus de bloquer.")
    os_name = get_os()
    if os_name == "linux":
        _block_linux(ip)
    else:
        _block_windows(ip)


def unblock_ip(ip: str) -> None:
    ip = _normalize_ip(ip)
    os_name = get_os()
    if os_name == "linux":
        _unblock_linux(ip)
    else:
        _unblock_windows(ip)
