# Smart SIEM — Guide de démarrage Semaine 1

## Prérequis

| Outil | Version minimale | Usage |
|---|---|---|
| Docker Engine | 24+ | Stack complète |
| Docker Compose | v2+ | Orchestration |
| Python 3.12 | 3.12+ | Mode local / scripts |
| openssl | tout | Génération TLS |

---

## Architecture S1

```
┌─────────────────────────────────────────────────────────┐
│  Sources de logs                                         │
│  ┌──────────────┐   ┌─────────────────┐                 │
│  │ infra/log_test│   │ scripts/seed/   │                 │
│  │ *.log (Linux) │   │ inject_logs.py  │                 │
│  └──────┬───────┘   └────────┬────────┘                 │
│         │                    │ HTTP bulk                 │
│         ▼                    │                           │
│  ┌──────────────┐            │                           │
│  │  Forwarder   │────────────┘                           │
│  │  (Python)    │  POST /api/v1/logs/ingest/bulk         │
│  └──────────────┘                                        │
│         │                                                │
│         ▼                                                │
│  ┌──────────────┐    ┌─────────────────────────────┐    │
│  │   Backend    │───▶│   Elasticsearch             │    │
│  │  FastAPI     │    │   index: smart-siem-logs    │    │
│  │  :8000       │    │   :9200                     │    │
│  └──────────────┘    └─────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

---

## Lancement rapide (Docker Compose)

```bash
# 1. Cloner le projet
cd /home/ems/Documents/projet\ Integrateur

# 2. Vérifier la configuration (.env déjà présent)
cat .env

# 3. Démarrer la stack
bash scripts/start.sh --build

# 4. Vérifier que tout fonctionne
bash scripts/validate.sh
```

---

## Lancement local (sans Docker)

```bash
# 1. Démarrer Elasticsearch manuellement (ou via Docker partiel)
docker run -d --name siem-es \
  -e discovery.type=single-node \
  -e xpack.security.enabled=false \
  -p 9200:9200 \
  docker.elastic.co/elasticsearch/elasticsearch:8.13.4

# 2. Installer les dépendances backend
cd backend
pip install -r requirements-dev.txt aiosqlite sqlalchemy[asyncio] asyncpg alembic apscheduler

# 3. Démarrer le backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# 4. (Terminal séparé) Démarrer le forwarder
LOG_DIR=infra/log_test BACKEND_URL=http://localhost:8000 python3 agents/forwarder.py
```

---

## Générer et injecter des logs de test

```bash
# Injecter 100 logs syslog via l'API (backend doit tourner)
python3 scripts/seed/inject_logs.py --count 100

# Injecter 1000 logs
python3 scripts/seed/inject_logs.py --count 1000

# Écrire dans infra/log_test/ (le forwarder les ingérera automatiquement)
python3 scripts/seed/inject_logs.py --count 500 --syslog

# Format JSON natif
python3 scripts/seed/inject_logs.py --count 100 --json

# Script shell simplifié
bash scripts/seed/generate_logs.sh 500
```

---

## Variables d'environnement importantes

| Variable | Défaut | Description |
|---|---|---|
| `ELASTICSEARCH_URL` | `http://localhost:9200` | URL Elasticsearch |
| `ELASTICSEARCH_USERNAME` | `elastic` | Auth ES |
| `ELASTICSEARCH_PASSWORD` | `changeme` | Mot de passe ES |
| `ES_LOGS_INDEX_NAME` | `smart-siem-logs` | Index des logs |
| `JWT_SECRET` | *(à changer en prod)* | Secret signature JWT |
| `INGEST_API_KEY` | `dev-only-change-me` | Clé API ingestion |
| `DATABASE_URL` | `sqlite+aiosqlite:///./siem.db` | DB utilisateurs |
| `RETENTION_DAYS` | `30` | Rétention logs (jours) |

---

## Comptes de démonstration (seedés au démarrage)

| Username | Mot de passe | Rôle |
|---|---|---|
| `admin` | `Admin1234!` | `administrator` |
| `analyst` | `Analyst1234!` | `analyst` |
| `reader` | `Reader1234!` | `reader` |

---

## Endpoints S1 disponibles

| Méthode | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/health` | Non | Santé du backend |
| GET | `/docs` | Non | Documentation Swagger |
| POST | `/api/auth/login` | Non | Connexion (retourne JWT) |
| POST | `/api/auth/logout` | Bearer | Déconnexion |
| POST | `/api/v1/logs/ingest` | X-API-Key | Ingestion syslog |
| POST | `/api/v1/logs/ingest/json` | X-API-Key | Ingestion JSON |
| POST | `/api/v1/logs/ingest/bulk` | X-API-Key | Ingestion en lot |
| GET | `/api/v1/logs` | Bearer (reader) | Lecture paginée |
| GET | `/api/v1/logs/{id}` | Bearer (reader) | Log par ID |
| GET | `/api/users` | Bearer (admin) | Liste utilisateurs |
| POST | `/api/users` | Bearer (admin) | Créer utilisateur |
| GET | `/api/audit` | Bearer (admin) | Journal d'audit |
| POST | `/api/admin/retention/run` | Bearer (admin) | Rétention manuelle |

---

## TLS — Préparation S1

Le TLS est désactivé en mode démo. Pour l'activer :

```bash
# 1. Générer les certificats
bash infra/tls/generate-certs.sh

# 2. Décommenter dans .env
#   SSL_CERTFILE=infra/certs/server.crt
#   SSL_KEYFILE=infra/certs/server.key

# 3. Démarrer avec TLS
uvicorn app.main:app \
  --ssl-certfile infra/certs/server.crt \
  --ssl-keyfile infra/certs/server.key

# 4. Pour Nginx en frontal : décommenter le service nginx dans docker-compose.yml
```

---

## Commandes de validation manuelle

```bash
# Santé backend
curl http://localhost:8000/health

# Login
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin1234!"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Ingestion d'un log syslog
curl -X POST http://localhost:8000/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-only-change-me" \
  -d '{"raw_message":"<34>Jun 30 12:00:00 srv01 sshd[1234]: Failed password for root from 10.0.0.1 port 22","source":"syslog"}'

# Lecture des logs
curl http://localhost:8000/api/v1/logs \
  -H "Authorization: Bearer $TOKEN"

# Elasticsearch — vérifier l'index
curl http://localhost:9200/smart-siem-logs/_count

# Validation complète automatique
bash scripts/validate.sh
```

---

## Arrêt de la stack

```bash
docker compose down          # Arrêt sans supprimer les données
docker compose down -v       # Arrêt + suppression des volumes (reset complet)
```

---

## Architecture Windows (préparation S1)

L'agent Windows n'est pas déployé en S1.  
Stratégie S2 prévue :
- **Winlogbeat** (agent Elastic) → lecture des Event Logs Windows → HTTP output → backend
- Format attendu : JSON natif via `/api/v1/logs/ingest/json`
- Config exemple : `agents/filebeat/filebeat.yml` (le même format s'applique à Winlogbeat)
- Priorité S2 : auth, réseau, système Windows

---

## Limitations connues S1

| Limitation | Statut | Prévu |
|---|---|---|
| TLS entre backend et ES | Désactivé en démo | S2 |
| Agent Windows | Non déployé | S2 |
| PostgreSQL (DB utilisateurs) | SQLite par défaut | S2 — configurable via DATABASE_URL |
| Réplication Elasticsearch | Single-node | S3 |
| Monitoring stack (Prometheus/Grafana) | Configuré mais non branché | S2 |
