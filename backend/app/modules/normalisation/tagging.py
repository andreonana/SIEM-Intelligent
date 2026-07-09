#   backend/app/modules/normalisation/tagging.py
#
#   Ce fichier applique la classification automatique stipulant que chaque log reçu doit recevoir un
#    tag de criticité (info, warning, critical) et un tag de type fonctionnel (auth, réseau, système, application).
#
#   Cette logique est volontairement séparée des analyseurs syntaxiques (parsers) car un parser sait lire un format 
#    de log, tandis qu'il sait classifier le contenu d'un log déjà lu.
#   En cas d'évolution des règles de classification, seul ce fichier sera modifié, et jamais les parsers.

from app.core.config import settings
from app.modules.normalisation.parsers.base import ParsedLog

def determine_severity(log: ParsedLog) -> str:
    """
    Détermine le niveau de criticité d'un log depuis des keywords présents dans son message brut.
    Cett implémentation utilise une recherche de keywords simpe, volontairement au lieur d'un système de règles complexe.
    Pour la classification d'un log individuel, la complexité supplémentaire d'un moteur de règles ne se justifie pas.
    La complexité réelle est réservée au futur module de corrélation qui travaillera sur plusieurs logs ensemble au lieu d'un log isolé.
    """
    #   .lower() est appliqué une seule fois ici, puis comparé à des keywords déjà en minuscules (core/config.py), cela évite de répérer
    #    la conversion en minuscule à chaque comparaison dans cette boucle
    message_lower = log.raw_message.lower()

    for keyword in settings.critical_keywords:
        if keyword.lower() in message_lower:
            return "critical"
        
    #   Règle secondaire simple: La présence du mot "warn" dans le message suffir à le classer en "warning".
    #   D'autres règles pourront être ajoutées ici au fil des tests réels d projet
    if "warn" in message_lower:
        return "warning"
    
    #   "info" est la valeur de repli par défaut: Tout log ni critique, ni avertissement est une information.
    #
    #   Ces 3 niveaux sont le tag de classification du log lui-même, différent des 4 niveaux d'aalerte (Info, Warning, High et Critical)
    #    qui seront gérés plus tard par le futur modèle de corrélation. Ce sont 2 concepts différents dans ce projet.
    return "info"

def determine_log_type(log: ParsedLog) -> str:
    """
    Détermine la catégorie fonctionnelle d'un log: authentification, réseau, système ou application.
    Même logique de simlicité volontaire que determinse_severity ci-dessus.
    """
    message_lower = log.raw_message.lower()

    #   On teste les keywords le splus spécifiques en premeir.
    #   "ssh" ou "password" sont quasiment certainement liés à l'authentification avant de chercher dnas le scatégories plus génériques
    #    si aucun keyword spécifique trouvé
    auth_keywords = ("password", "login", "authentication", "sshd", "logon")
    if any(keyword in message_lower for keyword in auth_keywords):
        return "auth"
    
    networks_keywords = ("firewall", "tcp", "udp", "connection refused", "port")
    if any(keyword in message_lower for keyword in networks_keywords):
        return "réseau"
    
    system_keywords = ("kernel", "cron", "systemd", "disk", "memory")
    if any(keyword in message_lower for keyword in system_keywords):
        return "système"
    
    #   Valeur de repli: Si aucun keyword connu ne correspond, le log est classé par défaut en "application"
    #    au lieu de lever une erreur. Un log non catégorisable ne doit jamais bloquer le pipeline d'ingestion
    return "application"