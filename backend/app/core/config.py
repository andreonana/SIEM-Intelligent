#   backend/app/core/config.py
#
#   *** POINT D'ENTREE UNIQUE DE TOUTE LA CONFIGURATION DE L'API    ***
#
#   Ce fichier est la SEUL endpoint du projet où toutes les variables de configuration de l'API sont
#    déclarées et documentées. Tout autre membre de l'équipe (Infra, data, frontend) ayant besoin de 
#    savoir comment se connecter à cette API, quelle variable mettre dans le fichier .env partagé, 
#    ou quel champ ce backend attend, n'a besoin de lire que ce fichier.
#
#   Ce fichier ne contient AUCUNE valeur secrète réelle: Toutes les valeurs sont lues à la racine du
#    projet (_SHARED_ENV_FILE ci-dessous), jamais écrites en dur ici.
#
#   D'autres fichiers du projet importent cet objet "settings" plutôt que de lire eux-mêmes des variables 
#    d'environnement directement; c'est ce qui permet de n'avoir qu'un seul fichier à modifier si une variable
#    doit changer de nom ou de valeur par défaut.

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from dataset.app import reports


#   Path(__file__) est le chemin de ce fichier (config.py) lui-même.
#   .resolve() le transforme en chemin absolu, pour un calcul fiable peu importe le répertoire de travail
#    courant au lancement.
#   .parents[3] remonte de 3 niveaux de dossiers parents depuis ce fichier:
#       backend/app/core/config.py -> backend/app/core -> backend/app -> backend -> [racine du projet].
#   C'est donc le 4e parent (index 3) qui correspond à la racine du projet, là où vit le fichier .env unique
#    partagé par toute l'équipe.
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_SHARED_ENV_FILE = _PROJECT_ROOT / ".env"

#   Paths to the different directories needs in the dataset folder
_DATA_DIR = _PROJECT_ROOT / "dataset"
_DATA_APP_REPORTS_DIR = _DATA_DIR / "app" / "reports"
_DATA_SCRIPTS_DIR = _DATA_DIR / "scripts"
_DATA_TESTS_DIR = _DATA_DIR / "tests"

class Settings(BaseSettings):
    """
    Configuration centralisée de l'API d'ingestion et de traitement des logs.
    Chaque champ ci-dessous correspond à UNE variable du fichier .env partagé. 
    La description de chaque champ indique qui doit fournir cette valeur et pourquoi elle est nécessaire.
    """

    #   ----------------------------------------------------------------------------------------
    #       SECTION:    Connexion à Elasticsearch
    #   ---------------------------------------------------------------------------------------

    #   Fournit par le responsable du data, en accord avec l'infra et la sécurité. C'est l'adresse réseau
    #    du cluster Elasticsearch auquel cette API se connecte pour stocker et lire les logs, s'authetifier 
    #    pour se connecter au cluster Elasticsearch (Optionnelle si elasticsearch_username/elasticsearch_password
    #    sont fournies à la place), avec le fichier de certificat correspondant (hors Git) pour vérifier l'authenticité
    #    de la connexion TLS au cluster Elasticsearch.
    elasticsearch_url:          str = "https://localhost:9200"
    elasticsearch_api_key:      str | None = None
    elasticsearch_username:     str | None = None
    elasticsearch_password:     str | None = None
    elasticsearch_ca_cert_path: str | None = None

    #   Nom de l'index où les logs normalisés sont stockés; et nom exact de l'index où les actions automatiques (
    #    nettoyage automatique de rétention) sont journalisées.
    es_logs_index_name:         str = "logs-siem"
    es_audit_index_name:        str = "smart-siem-audit"


    #   ----------------------------------------------------------------------------------------
    #       SECTION:    Sécurité locale à cette API (complément du RBAC)
    #   ----------------------------------------------------------------------------------------
    
    #   Fournit par l'équipe comme cl" statique simple pour une protection minimale de certains endpoints, en
    #    complément du système d'authentification JWT/RBAC complet.
    ingest_api_key:             str = "dev-only-change-me"

    #   Nombre maximal de requêtes acceptées par adresse IP appelante, sur la fenêtre de temps définie ci-dessous (anti-flood
    #    locale aux endpoints d'ingestion); et durée en secondes de fenêtre glissante utilisée par la limitation de débit.
    rate_limit_max_requests:    int = 100
    rate_limit_window_seconds:  int = 60

    #   ----------------------------------------------------------------------------------------
    #       SECTION:    JWT
    #   ----------------------------------------------------------------------------------------

    jwt_secret:                 str = "dev-only-change-me"
    jwt_algorithm:              str = "HS256"
    jwt_expiry_minutes:         int = 60

    #   ----------------------------------------------------------------------------------------
    #       SECTION:    Table tag -> severity
    #   ----------------------------------------------------------------------------------------

    #   Nom de l'index de la table de correspondance entre niveaux de severity et listes de tags associés. Un document par niveau
    #    de severity
    es_tag_severity_index_name: str = "smart-siem-tag-severity"

    #   Nom de l'index contenant les demandes de modification de la table tag -> severity, avec leur statut (en attente, validée, rejetée)
    es_tag_severity_update_index_name:  str = "smart-siem-tag-severity-update"

    #   ----------------------------------------------------------------------------------------
    #       SECTION:    KEYWORD DE RECONNAISSANCE DE SEVERITY PAR DEFAUT (INITIAUX)
    #   ----------------------------------------------------------------------------------------

    #   Critical keywords / keywords de niveau de severity critical
    critical_keywords:                  list[str] = [
        #   Authentification
        "brute force",
        "credential stuffing",
        "password spray",
        "POSSIBLE BREAK-IN",
        "repeated login failures",
        #   Malwares / intrusion
        "malware",
        "ransomware",
        "exploit",
        "rootkit",
        "backdoor",
        "trojan",
        "keylogger",
        "crypto miner",
        "cryptominer",
        #   Commande et contrôle
        "command and control",
        "c2 beacon",
        "reverse shell",
        "bind shell",
        #   Privilèges et accès non authorisé
        "privilege escalation",
        "unauthorized access",
        "illegal access",
        "sudo su -",
        "system compromised",
        "intrusion detected",
        #   Exfiltration
        "data exfiltration",
        "large upload",
        "bulk download",
        #   Réseau offensif
        "port scan",
        "arp spoofing",
        "dns poisoning",
        "man in the middle",
        #   Système critique
        "kernel panic",
        "system failure",
        "emergency",
    ]

    #   Warning keywords / Keywords de niveau warning
    warning_keywords:                       list[str] = [
        #   Echecs d'authentification simple
        "failed password",
        "authentication failure",
        "authentication error",
        "invalid user",
        "invalide credentials",
        "login failed",
        "logon failure",
        "access denied",
        "permission denied",
        #   Réseau
        "connection refused",
        "connection reset",
        "firewall deny",
        "firewall blocked",
        "port blocked",
        "suspicious traffic",
        "unknown source",
        #   TLS / certificats
        "certificate expired",
        "sel error",
        "ssl warning",
        "tls handshake failed",
        #   Ressource système
        "disk full",
        "low memory",
        "high cpu",
        "swap usage high",
        #   Services
        "service restarted",
        "daemon crash",
        "timeout",
        "retry limit",
        #   Générique
        "suspicious",
        "anomaly",
        "unusual activity",
        "decprecated",
    ] 

    #   ----------------------------------------------------------------------------------------
    #       SECTION:    Moteur de corrélation
    #   ----------------------------------------------------------------------------------------

    #   Nom exact de l'index dans lequel les alertes produites par le moteur de corrélation sont stockées (différent de l'index
    #    des logs eux-même)
    es_alerts_index_name: str = "smart-siem-alerts"

    #   Nombre d'échecs d'authentification depuis une même source pour vérification de brute force
    correlation_brute_force_threshold: int = 5

    #   Temps en seconde de vérification (failed authenticated on one source) pour la brute force
    correlation_brute_force_window_seconds: int = 60

    #   Fréquence en secondes à laquelle le job périodique de corrélation scanne automatiquement les logs récents. Le filet de sécurité général
    #    déclenche immédiatement
    correlation_scan_interval_seconds:      int = 3

    #   Tags prioritaire traversant le temps de vérification de correlation
    correlation_immediate_trigger_tags:     list[str] = [
        "brute force",
        "exfiltration",
        "failed password",
        "authentication failure",
        "outside hours",
        "communication banned",
        "log hidden",
        "unknown network",
    ]

    #   Niveaux de sévérity prioritaire traversant le temps de vérification de correlation
    correlation_immediate_trigger_severity: list[str] = [
        "critical",
        "warning",
    ]

    #   Activation et désactivation des règles de corrélation par l'admin
    es_rule_configs_index_name:             str = "smart-siem-rule-configs"

    #   ---------------------------------------------------------------------------------------
    #       SECTION:    Horaires de travail et détection hors-horaire
    #   ---------------------------------------------------------------------------------------

    #   Validation de l'admin
    approved_admins:                        list[str] = []

    #   Nom de l'index contenant la configuration des horaires de travail de l'entreprise (days and hours
    #    open, exceptions ponctuelles telles heures sup), gérée par un admin global.
    es_business_hours_index_name:           str = "smart-siem-business-hours"

    #   L'admin fournit le fuseau horaire lors de la configuration des horaires de travail pour adapter à la zone
    business_hours_timezone:                str = "UTC"

    #   ---------------------------------------------------------------------------------------
    #       SECTION:    Listes de références
    #   ---------------------------------------------------------------------------------------

    #   Inventaire des machines IP/MAC connues du réseau de l'entreprise, géré par un admin.
    #   Toute connexion depuis IP/MAC hors de cet inventaire est considérée comme suspecte.
    es_network_inventory_index_name:        str = "smart-siem-network-inventory"

    #   Index contenant les adresses IPs et domaines connus comme malveillants (réputation), géré par un admin
    es_threat_reputation_index_name:        str = "smart-siem-threat-reputation"

    #   Liste des noms de processus d'aministration à distance considérés comme inhabituels s'ils sont lancés sans
    #    justification comme des outils légitimes souvent utilisés à des fins malveillantes (AnyDesk, TeamViewer, ....).
    remote_admin_tools_watchlist:           list[str] = [
        "anydesk",
        "teamviewer",
        "psexec",
        "ammyy",
        "radmin",
        "vnc",
    ]

    #   Seuil de volume de données téléchargées au delà duquel le téléchargement est considéré comme massif.
    correlation_large_download_threshold_bytes: int = 5_000_000_000                 #   5 Go

    #   Nombre de fichiers modifiés/supprimés/chiffrés au-delà duquel l'activité est considérée comme massive
    correlation_mass_file_change_threshold:     int = 1000

    #   Nombre de ports distincts scannés depuis une même source, sur la fenêtre de corrélation, au delà duquel
    #    l'activité est considérée comme un scan de ports.
    correlation_port_scan_threshold:            int = 15

    #   Nombre d'hosts distincts contactés depuis une même source
    correlation_world_propagation_threshold:     int = 10

    #   Nombre de requêtes DNS distinctes depuis une même source
    correlation_dns_anomaly_threshold:          int = 100

    #   ----------------------------------------------------------------------------------------
    #       SECTION:    RETENTION DES LOGS
    #   ----------------------------------------------------------------------------------------

    #   Nombre total de jours au-delà duquel les logs sont supprimés automatiquement.
    retention_days:                             int = 30

    #   model_config configure comment Pydantic Settings lit les variables d'environnement.
    #       - env_file=".env" indique où se trouve le fichier .env partagé à la racine du projet backend.
    #       - extra="ignore" est essentiel car le fichier est partagé vue qu'il contient aussi des 
    #        variables utilisées par d'autres fichiers.
    #   Sans ce réglage, Pydantic lèverait une erreur de validation au démarrage dès qu'il 
    #    rencontre une variable du .env non expliqué explicitement comme champ de cette
    #    classe Settings précise.
    model_config = SettingsConfigDict(env_file=_SHARED_ENV_FILE, extra="ignore")

#   Instance unique, importée partout où ces réglages sont nécessaires.
settings = Settings()