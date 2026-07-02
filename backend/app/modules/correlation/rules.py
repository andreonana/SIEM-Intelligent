# backend/app/modules/correlation/rules.py
#
# Définition des 5 règles de corrélation hardcodées.
# Ces règles sont également persistées en SQL au démarrage (seed_correlation_rules).

from dataclasses import dataclass
from typing import Literal


@dataclass
class Rule:
    rule_id:         str
    name:            str
    description:     str
    rule_type:       Literal["threshold", "pattern"]
    severity:        str
    mitre_tactic:    str | None = None
    mitre_technique: str | None = None
    soar_action:     str | None = None
    threshold:       int | None = None
    window_minutes:  int = 10
    enabled:         bool = True


HARDCODED_RULES: list[Rule] = [
    Rule(
        rule_id="RULE_001",
        name="Brute Force SSH/Auth",
        description=(
            "Détection de tentatives d'authentification répétées en échec (brute force). "
            "Déclenché quand >= 5 événements d'échec auth proviennent de la même IP en 10 min."
        ),
        rule_type="threshold",
        threshold=5,
        window_minutes=10,
        severity="HIGH",
        mitre_tactic="Credential Access",
        mitre_technique="T1110",
        soar_action="block_ip",
    ),
    Rule(
        rule_id="RULE_002",
        name="Connexion hors horaires",
        description=(
            "Connexion détectée en dehors des heures ouvrées (avant 6h ou après 22h UTC). "
            "Peut indiquer un accès non autorisé ou un compte compromis."
        ),
        rule_type="pattern",
        window_minutes=10,
        severity="WARNING",
        mitre_tactic="Initial Access",
        mitre_technique="T1078",
    ),
    Rule(
        rule_id="RULE_003",
        name="Élévation de privilèges / modification de rôle non autorisée",
        description=(
            "Détection de commandes sudo, d'élévation de privilèges ou de modifications de rôle "
            "dans les logs système ou les logs d'audit SQL."
        ),
        rule_type="pattern",
        window_minutes=10,
        severity="HIGH",
        mitre_tactic="Privilege Escalation",
        mitre_technique="T1548",
        soar_action="escalate_admin",
    ),
    Rule(
        rule_id="RULE_004",
        name="Communication avec IP suspecte / exfiltration",
        description=(
            "Trafic réseau sortant suspect (outbound, data transfer, exfil) ou même source_ip "
            "détectée sur plus de 3 hôtes distincts dans la fenêtre temporelle."
        ),
        rule_type="pattern",
        window_minutes=10,
        severity="CRITICAL",
        mitre_tactic="Exfiltration",
        mitre_technique="T1041",
        soar_action="block_ip",
    ),
    Rule(
        rule_id="RULE_005",
        name="Arrêt du service de logs / dissimulation",
        description=(
            "Détection d'un arrêt ou d'une désactivation du service de journalisation "
            "(auditd, syslog, log rotation, logging disabled)."
        ),
        rule_type="pattern",
        window_minutes=10,
        severity="CRITICAL",
        mitre_tactic="Defense Evasion",
        mitre_technique="T1562",
        soar_action="escalate_admin",
    ),
]

# Index par rule_id pour accès rapide
RULES_BY_ID: dict[str, Rule] = {r.rule_id: r for r in HARDCODED_RULES}
