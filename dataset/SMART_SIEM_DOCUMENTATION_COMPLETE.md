en# Smart SIEM — Documentation technique et fonctionnelle complète

Date d'audit : 2026-07-04  
Périmètre audité : `/home/ems/Documents/projet Integrateur`  
Sources principales :
- code local réellement présent dans le dépôt ;
- cahier des charges : `/home/ems/Téléchargements/SIEM Intelligent V1.docx`.

Ce document décrit l'état réel du projet, relie les exigences du cahier des charges au code, explique la logique des principaux modules, donne les commandes d'installation/lancement/tests, et signale explicitement les écarts ou limites observés.

## 1. Présentation du projet

Smart SIEM est une plateforme de collecte, normalisation, stockage, recherche, corrélation et réponse à incident. Le projet vise un usage SOC pédagogique mais structuré autour d'éléments réels :
- ingestion HTTP, forwarder fichier et syslog UDP/TCP ;
- normalisation de logs vers Elasticsearch ;
- alerting et corrélation MITRE ATT&CK ;
- playbooks SOAR ;
- UEBA ;
- dashboard, recherche, investigation, rapports et audit ;
- authentification JWT avec MFA TOTP ;
- supervision de santé de la stack.

Profils visés par le CDC :
- analyste SOC ;
- RSSI / management sécurité ;
- auditeur / conformité ;
- administrateur de la plateforme.

## 2. Vue d'ensemble de l'architecture

### 2.1 Composants principaux

- `backend/` : API FastAPI, logique métier, SQLAlchemy, Elasticsearch, RBAC, corrélation, SOAR, UEBA.
- `frontend/` : interface React/Vite branchée aux endpoints backend.
- `infra/` : Nginx TLS, firewall-controller, éléments de test infra.
- `dataset/` : générateurs de logs, scénarios d'attaque, tests de validation complémentaires.
- `scripts/` : démarrage, validation, seed, résilience, CI shell.
- `docs/` : runbooks, rapports S1/S2/S3, schémas et sécurité.

### 2.2 Flux principaux

1. Source de log  
   `forwarder` fichier, `syslog-receiver` UDP/TCP, ou client HTTP.

2. Backend ingestion  
   `backend/app/api/v1/routers/logs.py` reçoit les logs, puis délègue à :
   - `backend/app/modules/ingestion/service.py`
   - `backend/app/modules/normalisation/*`

3. Stockage  
   Elasticsearch index `smart-siem-logs`.

4. Lecture et exploitation  
   - recherche : `backend/app/api/v1/routers/search.py`
   - investigation : `backend/app/api/v1/routers/investigation.py`
   - dashboard : `backend/app/api/v1/routers/dashboard.py`
   - alertes : `backend/app/api/v1/routers/alerts.py`
   - UEBA : `backend/app/api/v1/routers/ueba.py`

5. Réponse  
   - corrélation : `backend/app/modules/correlation/engine.py`
   - SOAR : `backend/app/modules/soar/*`
   - mails / webhooks : `backend/app/modules/alerting/notifier.py`
   - blocage IP réel : `infra/firewall-controller/`

## 3. Description des grandes parties du projet

### 3.1 Backend

Dossier principal : `backend/app/`

Sous-ensembles majeurs :
- `api/v1/routers/` : endpoints HTTP ;
- `modules/ingestion/` : ingestion et lecture ES ;
- `modules/normalisation/` : parsing, enrichissement, tagging ;
- `modules/correlation/` : moteur de règles S2/S3 ;
- `modules/soar/` : dispatcher AUTO/CONFIRM/MANUAL et playbooks ;
- `modules/ueba/` : baseline, analyse comportementale, anomalies, scoring ;
- `modules/rbac/` : JWT, rôles, MFA, rétention, protections locales ;
- `middleware/` : rate limiting, auth context, audit HTTP ;
- `services/` : alertes, audit, utilisateurs, exports, rapports, intégrité ;
- `models/` : tables SQL.

Point d'entrée :
- `backend/app/main.py`

Ce fichier initialise :
- la base SQL ;
- les seeds utilisateurs/règles ;
- les middlewares ;
- le scheduler de rétention ;
- le scheduler APScheduler pour le mode SOAR `CONFIRM` ;
- tous les routeurs de l'API.

### 3.2 Frontend

Dossier principal : `frontend/src/`

Points saillants :
- `services/api.js` : couche principale d'appel API ;
- `views/` : interface actuellement utilisée par `App.jsx` ;
- `pages/` : autre arborescence présente mais peu branchée dans l'app principale ;
- `components/` : widgets dashboard, charts, investigation, auth, UI.

Le frontend principal ne charge plus de répertoire `frontend/src/mocks/` ; `backend/tests/test_no_fake_data.py` vérifie explicitement l'absence de mocks.

### 3.3 Infrastructure

Fichiers clés :
- `docker-compose.yml`
- `infra/firewall-controller/`
- `infra/nginx/`
- `infra/log_test/`

Services Docker déclarés :
- `elasticsearch`
- `backend`
- `firewall-controller`
- `syslog-receiver`
- `forwarder`
- `nginx`

### 3.4 Sécurité

Éléments principaux :
- JWT + RBAC : `backend/app/modules/rbac/auth.py`, `roles.py`
- MFA TOTP RFC 6238 : `backend/app/modules/rbac/mfa.py`, `backend/app/api/v1/routers/auth.py`
- audit métier : `backend/app/services/audit_service.py`
- audit HTTP : `backend/app/middleware/audit_logger.py`
- rate limiting : `backend/app/middleware/rate_limiter.py`
- santé infra : `backend/app/api/v1/routers/system.py`
- SMTP réel : `backend/app/modules/alerting/notifier.py`
- firewall API réelle : `infra/firewall-controller/`

### 3.5 Data / dataset

Dossier principal : `dataset/`

Éléments présents :
- `dataset/generators/log_generator.py`
- `dataset/generators/attack_simulator.py`
- tests dédiés (`dataset/tests/`)

Le projet contient donc bien un outillage local pour générer un dataset 30 jours et des scénarios d'attaque, mais cette injection n'a pas été rejouée dans cet audit.

### 3.6 DevOps / scripts

Scripts utiles :
- `scripts/start.sh`
- `scripts/validate.sh`
- `scripts/test_resilience.sh`
- `scripts/seed/*`
- `scripts/security/*`

Observation :
- `scripts/ci/test.sh` est vide au moment de l'audit.

### 3.7 Tests

Arborescences :
- `backend/tests/`
- `dataset/tests/`
- `infra/firewall-controller/test_app.py`

Couverture visible :
- S1 ingestion/normalisation ;
- S2 alertes/corrélation/SOAR/UEBA ;
- S3 MFA / exports / dashboard / system health / V3 features ;
- garde-fou anti-fake-data ;
- scénarios sécurité mockés.

## 4. Correspondance cahier des charges ↔ code

### 4.1 Ingestion et normalisation

| Exigence CDC | Statut | Fichiers concernés | Ce que le code fait | Limites |
|---|---|---|---|---|
| Collecter des logs depuis plusieurs sources | Implémenté | `backend/app/api/v1/routers/logs.py`, `docker-compose.yml`, `syslog-receiver`, `forwarder` | Expose `/api/v1/logs/ingest`, `/ingest/json`, `/ingest/bulk`, et intègre forwarder + syslog receiver dans la stack | `ingest/bulk` est décrit comme outil de test dans les commentaires |
| Normaliser les logs | Implémenté | `backend/app/modules/normalisation/*` | Parse syslog/JSON, enrichit, taggue, alimente un schéma normalisé | Pas d'audit détaillé parser par parser dans ce document |
| Stocker dans Elasticsearch | Implémenté | `backend/app/modules/ingestion/service.py`, `backend/app/db/elasticsearch_client.py` | Indexation dans `smart-siem-logs` | Validé à l'exécution lors des tests manuels précédents |

### 4.2 Recherche et investigation

| Exigence CDC | Statut | Fichiers concernés | Ce que le code fait | Limites |
|---|---|---|---|---|
| Recherche multicritère | Partiel | `backend/app/api/v1/routers/search.py`, `frontend/src/views/LogExplorer.jsx.jsx`, `frontend/src/services/api.js` | Backend filtre par `source_ip`, `host`, `log_type`, `severity`, `username`, `start_date`, `end_date`; export CSV/XLSX disponible | Pas de `destination_ip` réel dans le pipeline ; le frontend principal filtre encore surtout localement sur les données chargées |
| Détail et timeline d'investigation | Partiel | `backend/app/api/v1/routers/investigation.py` | `GET /api/investigation/{entity_id}` reconstitue une timeline depuis ES ; `POST /flag` persiste un marquage suspect | Pas de vue frontend principale branchée à cette timeline dans `App.jsx` ; `frontend/src/pages/InvestigationPage.jsx` semble non utilisée |
| Pivoter sur un indicateur | Partiel | `backend/app/api/v1/routers/investigation.py` | Endpoint backend prêt | Bouton de pivot non constaté dans la vue principale auditée |

### 4.3 Corrélation et alertes

| Exigence CDC | Statut | Fichiers concernés | Ce que le code fait | Limites |
|---|---|---|---|---|
| Règles de corrélation MITRE | Implémenté en code, partiel en runtime | `backend/app/modules/correlation/engine.py`, `backend/app/models/rule.py`, `backend/app/services/alert_service.py` | Exécute des règles S2, crée des alertes, transporte tactique/technique MITRE, confidence score, SOAR auto | Validation runtime antérieure : `logs_analyzed: 0` malgré des logs présents dans ES ; donc moteur branché mais encore suspect sur la récupération réelle |
| Gestion des alertes | Implémenté | `backend/app/api/v1/routers/alerts.py`, `backend/app/services/alert_service.py`, `backend/app/models/alert.py` | Liste, détail, acknowledge, resolve, assign, export CSV/XLSX | Pas d'audit approfondi de tous les champs métier dans ce document |
| Déduplication anti-fatigue 5 min | Implémenté | `backend/app/services/alert_service.py` | Fenêtre de 5 minutes via clé de déduplication | Non revalidé à l'exécution dans cet audit, mais code et tests présents |

### 4.4 SOAR

| Exigence CDC | Statut | Fichiers concernés | Ce que le code fait | Limites |
|---|---|---|---|---|
| Playbooks SOAR | Implémenté | `backend/app/modules/soar/playbooks.py`, `backend/app/api/v1/routers/soar.py` | `block_ip`, `disable_account`, `escalate_admin` | `block_ip` dépend de `FIREWALL_API_URL`; l'effet réel dépend donc du service firewall |
| Auto-déclenchement | Implémenté | `backend/app/modules/correlation/engine.py`, `backend/app/modules/soar/dispatcher.py` | Déclenche automatiquement le playbook quand `soar_action` est défini | API règles n'expose pas encore tous les champs V3 associés |
| Modes AUTO / CONFIRM / MANUAL | Implémenté | `backend/app/modules/soar/dispatcher.py`, `backend/app/main.py`, `backend/app/models/rule.py` | `AUTO` immédiat, `CONFIRM` planifié via APScheduler, `MANUAL` sans auto-run | Route d'administration des règles encore incomplète pour `soar_mode` et `confirm_delay_seconds` |
| Email réel | Implémenté | `backend/app/modules/alerting/notifier.py` | Envoi SMTP réel via `aiosmtplib` | Dépend des secrets SMTP réels du `.env` |

### 4.5 UEBA

| Exigence CDC | Statut | Fichiers concernés | Ce que le code fait | Limites |
|---|---|---|---|---|
| Baseline comportementale | Implémenté | `backend/app/modules/ueba/baseline.py` | Calcule baseline par `user`, `source_ip` ou `host` | Risque de couverture partielle si les logs ne portent pas `user/username` |
| Détection d'anomalies | Implémenté | `backend/app/modules/ueba/behavior_analyzer.py`, `anomaly_detector.py` | Compare comportement récent et baseline, persiste des anomalies | Une partie de la logique lit `message` alors que les logs normalisés utilisent souvent `raw_message` |
| Risk scoring | Implémenté | `backend/app/modules/ueba/risk_scorer.py`, `backend/app/models/ueba_*`, `backend/app/api/v1/routers/ueba.py` | Score 0-100, niveau low/medium/high/critical, endpoints de lecture et d'analyse | Fonctionnellement plausible, mais pas entièrement revalidé bout en bout sur données réelles |

### 4.6 MFA

| Exigence CDC | Statut | Fichiers concernés | Ce que le code fait | Limites |
|---|---|---|---|---|
| MFA TOTP RFC 6238 | Implémenté | `backend/app/modules/rbac/mfa.py`, `backend/app/api/v1/routers/auth.py`, `backend/app/models/user.py`, `backend/tests/unit/s3/test_mfa.py` | Setup secret + provisioning URI, verify setup, login en 2 étapes, disable MFA, audit | Pas de QR code image généré ; URI `otpauth://` fournie |

### 4.7 Rapports PDF

| Exigence CDC | Statut | Fichiers concernés | Ce que le code fait | Limites |
|---|---|---|---|---|
| Rapport PDF 7 jours | Implémenté | `backend/app/api/v1/routers/reports.py`, `backend/app/services/report_service.py` | Agrège ES + SQL et génère un PDF via `reportlab`; expose aussi un summary JSON | Le rapport dépend de la qualité des données présentes en base/ES |

### 4.8 Exports CSV / Excel

| Exigence CDC | Statut | Fichiers concernés | Ce que le code fait | Limites |
|---|---|---|---|---|
| Export logs filtrés | Implémenté | `backend/app/api/v1/routers/search.py`, `backend/app/services/export_service.py`, `frontend/src/services/api.js` | Exports CSV/XLSX des résultats de recherche | Le frontend principal n'expose pas encore tous les filtres backend disponibles |
| Export alertes | Implémenté | `backend/app/api/v1/routers/alerts.py`, `frontend/src/services/api.js` | Exports CSV/XLSX des alertes filtrées | Aucun problème majeur constaté dans le code |

### 4.9 Dashboard et vues par profil

| Exigence CDC | Statut | Fichiers concernés | Ce que le code fait | Limites |
|---|---|---|---|---|
| Dashboard réel | Implémenté | `backend/app/api/v1/routers/dashboard.py`, `frontend/src/views/Dashboard.jsx`, `frontend/src/components/WorldAttackMap.jsx` | Agrège logs/histogramme/top alertes/top IPs ; frontend recharge périodiquement | Fallback client encore utilisé si agrégation serveur indisponible |
| Vue RSSI | Implémenté | `frontend/src/views/RSSIView.jsx` | KPIs macro, incidents majeurs, entités à risque UEBA, audit count | Dépend des données remontées par les vues backend existantes |
| Vue analyste | Implémenté partiellement | `frontend/src/views/Dashboard.jsx`, `AlertTriage.jsx`, `LogExplorer.jsx.jsx` | Dashboard, alertes, logs, playbooks, crisis room | Investigation détaillée encore incomplète côté UI |
| Vue auditeur conformité | Implémenté partiellement | `frontend/src/views/Compliance.jsx` | Audit, intégrité, événements liés aux données, export alertes | Le composant dit explicitement qu'aucun score ISO 27001 / RGPD n'est calculé |

### 4.10 Crisis Room

| Exigence CDC | Statut | Fichiers concernés | Ce que le code fait | Limites |
|---|---|---|---|---|
| Salle de crise avec auto-refresh 5s | Implémenté | `frontend/src/views/CrisisRoom.jsx` | Rafraîchissement toutes les 5 secondes, checklist de clôture, résolution d'alerte | Dépend des alertes déjà chargées dans l'état frontend |

### 4.11 Sécurité, audit, santé, TLS, rétention

| Exigence CDC | Statut | Fichiers concernés | Ce que le code fait | Limites |
|---|---|---|---|---|
| RBAC + auth locale | Implémenté | `backend/app/modules/rbac/*`, `backend/app/api/v1/routers/auth.py`, `users.py` | JWT, rôles `reader/analyst/administrator`, seed users | Comptes seedés au démarrage |
| Audit | Implémenté | `backend/app/services/audit_service.py`, `backend/app/api/v1/routers/audit.py`, `backend/app/middleware/audit_logger.py` | Audit métier et audit HTTP | Audit HTTP filtré pour éviter le flood |
| Rate limiting | Implémenté | `backend/app/middleware/rate_limiter.py`, `logs.py` | Limitation de débit middleware + protection locale ingestion | Redondance possible avec `enforce_rate_limit` dans `logs.py` |
| TLS | Implémenté partiellement | `docker-compose.yml`, `nginx`, docs S1/S2 | Nginx exposé en 443, tests HTTPS déjà validés dans Docker | Gestion certificats orientée démo / runbook, pas auditée en profondeur ici |
| Rétention | Partiellement auditée | `backend/app/modules/rbac/retention.py`, `backend/app/main.py` | Scheduler démarré dans `main.py` | Fonction non relue en détail dans cet audit |
| Santé infrastructure | Implémenté | `backend/app/api/v1/routers/system.py`, `frontend/src/views/SystemConfig.jsx` | Vérifie backend, ES, nginx, syslog, forwarder (indirect) | Forwarder vérifié indirectement via fraîcheur du dernier log, pas par vraie sonde |

### 4.12 Chaîne de custody SHA-256

| Exigence CDC | Statut | Fichiers concernés | Ce que le code fait | Limites |
|---|---|---|---|---|
| Hash SHA-256 par batch + vérification | Partiel | `backend/app/models/log_batch.py`, `backend/app/services/integrity_service.py`, `backend/app/api/v1/routers/integrity.py` | Enregistre batch hashé, parent hash, vérification d'intégrité, liste des batches | `record_batch()` n'est appelé nulle part dans le flux d'ingestion audité ; la chaîne existe en code et en API, mais n'est pas branchée automatiquement à l'ingestion réelle |

### 4.13 Dataset 30 jours / attaques cachées / livrables

| Exigence CDC | Statut | Fichiers concernés | Ce que le code fait | Limites |
|---|---|---|---|---|
| Dataset 30 jours + 3 attaques cachées | Partiel | `dataset/generators/log_generator.py`, `dataset/generators/attack_simulator.py`, `backend/tests/security/test_attack_scenarios.py` | Générateurs présents ; tests de scénarios sécurité présents | Les tests sécurité sont mockés ; l'injection complète du dataset n'a pas été rejouée dans cet audit |
| Documentation et runbooks | Implémenté partiellement | `README.md`, `GUIDE_DEMARRAGE.md`, `docs/runbooks/*`, `docs/rapports/*` | Documentation abondante disponible | Certaines affirmations doivent être recoupées au code ; ce document sert précisément à cette mise au clair |

## 5. Explication détaillée du code par domaine

### 5.1 Authentification et MFA

- `backend/app/api/v1/routers/auth.py`
  - `POST /api/auth/login` :
    - retourne un JWT complet si MFA désactivé ;
    - retourne `mfa_required=true` et un `mfa_token` 5 minutes si MFA activé.
  - `POST /api/auth/mfa/verify` :
    - consomme le token intermédiaire et un code TOTP 6 chiffres ;
    - délivre le JWT final.
  - `POST /api/auth/mfa/setup` :
    - génère un secret TOTP ;
    - le stocke ;
    - retourne l'URI `otpauth://`.
  - `POST /api/auth/mfa/verify-setup` :
    - active effectivement MFA après validation du premier code.
  - `GET /api/auth/mfa/status`, `POST /api/auth/mfa/disable`.

- `backend/app/modules/rbac/mfa.py`
  - s'appuie sur `pyotp` ;
  - expose la génération, le provisioning URI, la vérification TOTP et le token intermédiaire MFA.

### 5.2 Ingestion et lecture de logs

- `backend/app/api/v1/routers/logs.py`
  - endpoints d'ingestion protégés par clé API simple et limitation de débit ;
  - endpoints de lecture protégés par RBAC.

- `backend/app/modules/ingestion/read_service.py`
  - pagination et récupération d'un log par ID dans Elasticsearch.

### 5.3 Recherche et export

- `backend/app/api/v1/routers/search.py`
  - construit une requête ES `bool/filter` ;
  - expose la recherche et les exports CSV/XLSX.

- `frontend/src/services/api.js`
  - `searchLogs`, `exportLogsCsv`, `exportLogsXlsx`.

- `frontend/src/views/LogExplorer.jsx.jsx`
  - vue utilisée dans l'application principale ;
  - reste orientée filtrage local sur les logs déjà chargés, avec export branché au backend.

### 5.4 Corrélation et alerting

- `backend/app/modules/correlation/engine.py`
  - récupère les logs depuis ES ;
  - évalue les règles ;
  - crée des alertes ;
  - transmet confidence score et déclenche SOAR si défini.

- `backend/app/services/alert_service.py`
  - persistance SQL des alertes ;
  - acknowledge, resolve, assign ;
  - déduplication 5 minutes ;
  - seed des règles par défaut.

### 5.5 SOAR

- `backend/app/modules/soar/playbooks.py`
  - `block_ip` :
    - appelle `POST {FIREWALL_API_URL}/block` ;
    - échoue honnêtement si la config manque ;
    - lit le corps JSON réel de la réponse firewall.
  - `disable_account` :
    - désactive un utilisateur SQL.
  - `escalate_admin` :
    - notifie Slack/Teams/email selon la config.

- `backend/app/modules/soar/dispatcher.py`
  - orchestre `AUTO`, `CONFIRM`, `MANUAL` ;
  - planifie `CONFIRM` via APScheduler.

### 5.6 UEBA

- `backend/app/modules/ueba/baseline.py`
  - reconstruit la baseline par entité.
- `behavior_analyzer.py`
  - agrège le comportement récent.
- `anomaly_detector.py`
  - compare baseline et fenêtre récente.
- `risk_scorer.py`
  - calcule score et niveau de risque.
- `backend/app/services/ueba_service.py`
  - orchestre le pipeline complet et la persistance SQL.

### 5.7 Rapports

- `backend/app/services/report_service.py`
  - agrège ES, alertes SQL, audit SQL, UEBA SQL ;
  - génère un PDF via `reportlab`.

- `backend/app/api/v1/routers/reports.py`
  - expose le summary JSON et le PDF.

### 5.8 Dashboard, profils et supervision

- `backend/app/api/v1/routers/dashboard.py`
  - agrège total logs, histogramme horaire, top IP sources, alertes actives.

- `frontend/src/views/Dashboard.jsx`
  - utilise l'agrégation serveur, avec fallback client.

- `frontend/src/views/RSSIView.jsx`
  - synthèse management.

- `frontend/src/views/Compliance.jsx`
  - vue auditeur, sans faux score conformité.

- `frontend/src/views/CrisisRoom.jsx`
  - salle de crise avec refresh 5s.

- `backend/app/api/v1/routers/system.py`
  - santé réelle de la stack.

## 6. Installation et configuration

## 6.1 Prérequis

- Docker Engine + Docker Compose v2
- Python 3.12+
- Node.js compatible Vite 8
- `curl`
- `python3`

## 6.2 Variables d'environnement

Le backend charge `.env` à la racine du projet via `load_dotenv()` dans `backend/app/main.py`.

Variables importantes détectées dans le code :
- `ELASTICSEARCH_URL`
- `ES_LOGS_INDEX_NAME`
- `DATABASE_URL`
- `JWT_SECRET`
- `INGEST_API_KEY`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASSWORD`
- `ALERT_EMAIL_TO`
- `FIREWALL_API_URL`
- `MFA_ISSUER_NAME`
- `MFA_TIME_STEP`
- `MFA_ALLOWED_DRIFT`

Ne pas republier les secrets du `.env` dans la documentation partagée.

## 6.3 Installation backend

```bash
cd "/home/ems/Documents/projet Integrateur/backend"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## 6.4 Installation frontend

```bash
cd "/home/ems/Documents/projet Integrateur/frontend"
npm install
```

## 7. Lancement du projet

## 7.1 Stack Docker complète

```bash
cd "/home/ems/Documents/projet Integrateur"
docker compose up -d --no-build
docker compose ps
```

Option script projet :

```bash
cd "/home/ems/Documents/projet Integrateur"
bash scripts/start.sh
```

## 7.2 Backend local

```bash
cd "/home/ems/Documents/projet Integrateur/backend"
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## 7.3 Frontend local

```bash
cd "/home/ems/Documents/projet Integrateur/frontend"
npm run dev -- --host 0.0.0.0 --port 5173
```

## 7.4 Vérifications de base

```bash
curl -s http://localhost:8000/health
curl -s http://localhost:9200/_cluster/health
curl -s http://localhost:8080/health
```

## 8. Exécution / démonstration

## 8.1 Login

```bash
set +H
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin1234!"}' \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")
echo "$TOKEN"
```

## 8.2 Ingestion directe

```bash
curl -X POST http://localhost:8000/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-only-change-me" \
  -d '{"raw_message":"<34>Jun 30 12:34:56 test-srv sshd[999]: Failed password for root from 10.123.45.67 port 22","source":"syslog"}'
```

## 8.3 Vérification Elasticsearch

```bash
curl http://localhost:9200/smart-siem-logs/_count
```

## 8.4 Syslog UDP/TCP réel

```bash
docker compose exec backend python -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'<34>Jun 30 15:22:00 udp-srv sshd[2201]: Failed password for root from 10.88.77.66 port 22\n', ('syslog-receiver', 5140)); print('udp_sent')"

docker compose exec backend python -c "import socket; s=socket.create_connection(('syslog-receiver', 5140), timeout=5); s.sendall(b'<34>Jun 30 15:23:00 tcp-srv sshd[2202]: Failed password for root from 10.88.77.67 port 22\n'); s.close(); print('tcp_sent')"
```

## 8.5 Recherche

```bash
curl -s -X POST "http://localhost:8000/api/search" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"severity":"critical","page_size":10}'
```

## 8.6 Alertes

```bash
curl -s "http://localhost:8000/api/alerts?page_size=20" \
  -H "Authorization: Bearer $TOKEN"
```

## 8.7 Corrélation

```bash
curl -s -X POST http://localhost:8000/api/correlation/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"window_minutes":180}'
```

Attention : lors des validations manuelles précédentes, cet endpoint répondait mais retournait souvent `logs_analyzed: 0`.

## 8.8 UEBA

```bash
curl -s -X POST http://localhost:8000/api/ueba/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"entity_type":"source_ip","baseline_days":30,"window_minutes":180}'

curl -s "http://localhost:8000/api/ueba/risk-scores" \
  -H "Authorization: Bearer $TOKEN"
```

## 8.9 SOAR

```bash
curl -s -X POST http://localhost:8000/api/soar/playbooks/block_ip/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"params":{"ip":"203.0.113.50","reason":"test manuel"}}'
```

## 8.10 Rapport PDF

```bash
curl -s "http://localhost:8000/api/reports/weekly?days=7" \
  -H "Authorization: Bearer $TOKEN" \
  -o rapport-hebdo.pdf
```

## 8.11 Exports

```bash
curl -s -X POST "http://localhost:8000/api/search/export.csv" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"page_size":100}' \
  -o logs_export.csv

curl -s "http://localhost:8000/api/alerts/export.csv" \
  -H "Authorization: Bearer $TOKEN" \
  -o alerts_export.csv
```

## 8.12 Investigation

```bash
curl -s "http://localhost:8000/api/investigation/10.88.77.66" \
  -H "Authorization: Bearer $TOKEN"

curl -s -X POST "http://localhost:8000/api/investigation/10.88.77.66/flag" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"note":"entité suspecte"}'
```

## 8.13 Santé système

```bash
curl -s "http://localhost:8000/api/system/health" \
  -H "Authorization: Bearer $TOKEN"
```

## 8.14 Intégrité SHA-256

```bash
curl -s "http://localhost:8000/api/integrity/batches" \
  -H "Authorization: Bearer $TOKEN"
```

Attention : l'API existe, mais aucun branchement automatique de `record_batch()` au pipeline d'ingestion n'a été trouvé dans le code audité.

## 9. Commandes de test

## 9.1 Validation shell fournie par le projet

```bash
cd "/home/ems/Documents/projet Integrateur"
bash scripts/validate.sh
bash scripts/test_resilience.sh
```

## 9.2 Tests backend

```bash
cd "/home/ems/Documents/projet Integrateur/backend"
python3 -m pytest tests/ -v
python3 -m pytest tests/test_no_fake_data.py -v
python3 -m pytest tests/unit/s2/ -v
python3 -m pytest tests/unit/s3/ -v
python3 -m pytest tests/security/ -v
```

## 9.3 Tests firewall-controller

```bash
cd "/home/ems/Documents/projet Integrateur/infra/firewall-controller"
python3 -m pytest test_app.py -v
```

## 9.4 Vérification frontend

```bash
cd "/home/ems/Documents/projet Integrateur/frontend"
npm run build
npm run lint
```

Observation :
- aucun test unitaire frontend n'a été identifié dans `package.json` ;
- `scripts/ci/test.sh` est vide.

## 10. Limites, écarts et dette technique

1. Corrélation :
   le moteur est présent et sophistiqué, mais des validations réelles ont déjà montré `logs_analyzed: 0` alors que des logs existent dans Elasticsearch.

2. Chaîne de custody :
   `record_batch()` existe, mais n'est pas appelée depuis le flux d'ingestion audité.

3. API règles :
   `backend/app/models/rule.py` supporte `confidence_score`, `soar_mode`, `confirm_delay_seconds`, mais `backend/app/api/v1/routers/rules.py` n'expose pas encore ces champs en création/mise à jour.

4. Recherche / investigation :
   - pas de `destination_ip` réel côté backend ;
   - pas de détail de log dédié dans `search.py` ;
   - la vue principale `LogExplorer` repose surtout sur les données déjà chargées dans l'état client ;
   - le pivot / timeline backend ne sont pas pleinement exploités dans l'UI principale.

5. UEBA :
   certains traitements semblent conçus autour de `message`, `user`, `username`, alors que les logs normalisés exposent surtout `raw_message`, `source_ip`, `host`, `log_type`.

6. Documentation et scripts :
   plusieurs documents projet existent, mais certaines affirmations doivent être prises avec prudence sans recoupement code/runtime.

7. Scripts CI :
   `scripts/ci/test.sh` est vide.

8. Frontend :
   présence d'un fichier au nom anormal `frontend/src/views/LogExplorer.jsx.jsx`, signe de dette de structure.

9. Tests sécurité dataset :
   `backend/tests/security/test_attack_scenarios.py` couvre bien les scénarios attendus, mais uniquement avec mocks.

## 11. Conclusion

État global :
- le projet a dépassé le stade de squelette ;
- l'architecture backend est riche et cohérente ;
- le frontend principal est branché à l'API réelle sur plusieurs flux clés ;
- MFA, exports, dashboard, santé système, rapports PDF, SOAR et UEBA existent en code ;
- plusieurs points V3 sont effectivement présents.

Niveau de conformité au cahier des charges :
- conforme sur une grande partie des briques techniques attendues ;
- partiellement conforme sur les flux qui demandent encore une intégration bout en bout irréprochable :
  - corrélation runtime,
  - chaîne SHA-256 branchée à l'ingestion,
  - investigation frontend,
  - exposition complète des paramètres de règles V3.

Prêt pour soutenance :
- oui pour démontrer l'architecture, les endpoints, les exports, le PDF, le MFA, le SOAR, la supervision et la collecte multi-source ;
- avec réserves à expliciter honnêtement sur la corrélation réelle, l'intégrité branchée, et certaines parties investigation/UEBA.

À terminer en priorité :
1. brancher `record_batch()` au pipeline d'ingestion réel ;
2. corriger définitivement la récupération ES du moteur de corrélation ;
3. compléter l'API `rules` avec `confidence_score`, `soar_mode`, `confirm_delay_seconds` ;
4. brancher la timeline/pivot/flag d'investigation dans l'UI principale ;
5. réaligner UEBA sur le schéma réel des logs normalisés.

