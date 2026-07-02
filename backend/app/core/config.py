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

#   Path(__file__) est le chemin de ce fichier (config.py) lui-même.
#   .resolve() le transforme en chemin absolu, pour un calcul fiable peu importe le répertoire de travail
#    courant au lancement.
#   .parents[3] remonte de 3 niveaux de dossiers parents depuis ce fichier:
#       backend/app/core/config.py -> backend/app/core -> backend/app -> backend -> [racine du projet].
#   C'est donc le 4e parent (index 3) qui correspond à la racine du projet, là où vit le fichier .env unique
#    partagé par toute l'équipe.
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_SHARED_ENV_FILE = _PROJECT_ROOT / ".env"

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
    es_logs_index_name:         str = "smart-siem-logs"
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

    #   Politique de mots de passe — longueur minimale requise (vérifiée dans user_service).
    password_min_length:        int = 8

    #   Nombre maximal de tentatives de connexion avant verrouillage (documenté ici, non encore appliqué en S2).
    max_login_attempts:         int = 5

    #   Durée de validité de la session en minutes (alignée sur JWT_EXPIRY_MINUTES).
    session_timeout_minutes:    int = 60


    #   ----------------------------------------------------------------------------------------
    #       SECTION:    Base de données relationnelle (utilisateurs, audit)
    #   ----------------------------------------------------------------------------------------

    #   URL SQLAlchemy async. Exemples :
    #     PostgreSQL  : postgresql+asyncpg://siem:siem1234@localhost:5432/siem_db
    #     SQLite demo : sqlite+aiosqlite:///./siem.db   (créé automatiquement)
    #   Si absent, le backend bascule sur SQLite local (demo/CI uniquement).
    database_url: str = "sqlite+aiosqlite:///./siem.db"

    #   ----------------------------------------------------------------------------------------
    #       SECTION:    Rétention des logs
    #   ----------------------------------------------------------------------------------------

    #   Durée de rétention en jours pour les logs Elasticsearch (RETENTION_DAYS dans .env).
    retention_days: int = 30

    #   Mettre à false pour désactiver le scheduler APScheduler (utile en tests / CI).
    enable_retention_scheduler: bool = True

    #   ----------------------------------------------------------------------------------------
    #       SECTION:    JWT — sécurité authentification
    #   ----------------------------------------------------------------------------------------

    #   Secret JWT — doit être fourni via JWT_SECRET dans .env.
    #   Pas de valeur par défaut ici : la vérification est faite dans rbac/auth.py au démarrage.
    jwt_secret: str | None = None
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60

    #   ----------------------------------------------------------------------------------------
    #       SECTION:    Classification automatique des logs (normalisation)
    #   ----------------------------------------------------------------------------------------

    #   Liste de keywords déclenchant un criticité "critical".
    critical_keywords:          list[str] = [
        "failed password",
        "authentication failure",
        "denied",
    ]

    #   ----------------------------------------------------------------------------------------
    #       SECTION:    Notifications S2 (Slack, Teams, Email)
    #   ----------------------------------------------------------------------------------------

    slack_webhook_url:  str | None = None
    teams_webhook_url:  str | None = None
    smtp_host:          str | None = None
    smtp_port:          int = 587
    smtp_user:          str | None = None
    smtp_password:      str | None = None
    alert_email_to:     str | None = None

    #   ----------------------------------------------------------------------------------------
    #       SECTION:    SOAR
    #   ----------------------------------------------------------------------------------------

    #   ----------------------------------------------------------------------------------------
    #       SECTION:    MFA TOTP (RFC 6238)
    #   ----------------------------------------------------------------------------------------

    # Nom de l'émetteur affiché dans les apps authenticator (Google Authenticator, Authy…).
    mfa_issuer_name: str = "Smart SIEM"

    # Durée d'un intervalle TOTP en secondes (RFC 6238 recommande 30s).
    mfa_time_step: int = 30

    # Fenêtre de tolérance en nombre d'intervalles de chaque côté de l'heure courante.
    # 1 = ±30s de tolérance sur la dérive d'horloge.
    mfa_allowed_drift: int = 1

    #   ----------------------------------------------------------------------------------------
    #       SECTION:    Rapports PDF
    #   ----------------------------------------------------------------------------------------

    # Fenêtre par défaut du rapport hebdomadaire en jours.
    reports_default_days: int = 7

    #   ----------------------------------------------------------------------------------------
    #       SECTION:    UEBA — Analyse comportementale
    #   ----------------------------------------------------------------------------------------

    # Fenêtre en jours utilisée pour construire la baseline comportementale.
    ueba_baseline_days: int = 30

    # Fenêtre en minutes pour l'analyse comportementale récente (comparée à la baseline).
    ueba_analysis_window_minutes: int = 60

    # Nombre minimal d'événements dans la fenêtre de baseline pour qu'elle soit fiable.
    ueba_min_events_for_baseline: int = 5

    # Seuils de score de risque.
    ueba_risk_medium_threshold: int = 20
    ueba_risk_high_threshold: int = 45
    ueba_risk_critical_threshold: int = 70

    #   ----------------------------------------------------------------------------------------
    #       SECTION:    SOAR
    #   ----------------------------------------------------------------------------------------

    #   URL du service firewall réel (voir infra/firewall-controller/) consommé par le
    #   playbook SOAR block_ip. Contrat HTTP : POST {url}/block {"ip", "reason"} ->
    #   {"status": "blocked"|"failure", ...}. Si absent, block_ip échoue explicitement
    #   (status=failure) — aucune simulation de blocage n'est effectuée.
    firewall_api_url:   str | None = None

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