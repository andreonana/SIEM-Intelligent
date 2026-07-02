# Smart SIEM — Plateforme de Gestion et d'Analyse des Événements de Sécurité

Projet étudiant (équipe de 5-6) — 3 semaines

## Modules fonctionnels
1. Collecte et normalisation des logs
2. Stockage, indexation et conservation
3. Corrélation d'événements (MITRE ATT&CK)
4. Alertes et réponse aux incidents (SOAR)
5. Visualisation et reporting
6. Recherche et investigation forensique
7. Gestion des utilisateurs et sécurité d'accès (RBAC/MFA)
8. Analyse comportementale UEBA

## Stack
- **Backend** : Python (FastAPI) / Node.js
- **Frontend** : React + Vite + Tailwind CSS
- **BDD** : Elasticsearch + PostgreSQL
- **Agents** : Syslog / Filebeat custom
- **Infra** : Docker / Docker Compose

## Organisation des branches

### Convention de nommage

Les branches suivent le schéma `<poste>/<semaine>` :

| Poste | S1 | S2 | S3 |
|---|---|---|---|
| Chef de projet | `chef-projet/S1` | `chef-projet/S2` | `chef-projet/S3` |
| Développeur Backend | `backend/S1` | `backend/S2` | `backend/S3` |
| Développeur Frontend | `frontend/S1` | `frontend/S2` | `frontend/S3` |
| Ingénieur Infrastructure | `infrastructure/S1` | `infrastructure/S2` | `infrastructure/S3` |
| Ingénieur Data | `data/S1` | `data/S2` | `data/S3` |
| Ingénieur DevOps | `devops/S1` | `devops/S2` | `devops/S3` |

### Pourquoi cette structuration ?

**Isolation par poste** — chaque membre travaille dans sa propre branche sans risquer d'écraser le travail d'un autre. Les conflits de fusion sont détectés et résolus consciemment lors des PR, pas par surprise.

**Isolation par semaine** — une branche par semaine crée un point de livraison clair à chaque fin de sprint. `S1` se ferme par une PR vers `main` avant que `S2` ne commence, ce qui donne un historique lisible : on peut retrouver exactement ce qui a été produit chaque semaine par chaque rôle.

**Traçabilité et revue de code** — toute modification passe par une Pull Request. Le chef de projet (ou un pair) valide avant que le code n'intègre `main`, ce qui évite d'introduire du code cassé dans la base commune.

**Parallélisme sans blocage** — les 6 membres travaillent simultanément sur leurs branches respectives. Il n'y a pas de verrou : le backend et le frontend avancent en même temps sans attendre l'autre.

### Flux de travail

```
main  ←─── PR fin de semaine ───  backend/S1
                                   frontend/S1
                                   infrastructure/S1
                                   ...
```

1. Cloner le dépôt et se positionner sur sa branche : `git checkout backend/S1`
2. Travailler, committer régulièrement
3. En fin de semaine : ouvrir une Pull Request vers `main`
4. Après merge : passer sur la branche suivante : `git checkout backend/S2`

---

## Prérequis

- Docker + Docker Compose (v2)
- Python 3.12+ (pour exécuter les tests backend hors conteneur)
- Node.js 20+ et npm (pour le développement frontend hors conteneur)
- 4 Go de RAM disponibles minimum (Elasticsearch)

## Démarrage rapide

```bash
cp .env.example .env
# Éditer .env : remplacer au minimum JWT_SECRET, INGEST_API_KEY, ELASTICSEARCH_PASSWORD
docker compose up -d
```

Vérifier que tout démarre :
```bash
curl http://localhost:8000/health          # backend
curl -k https://localhost/                 # frontend via nginx (443)
```

### Développement frontend en local (hors conteneur)

```bash
cd frontend
npm install
npm run dev          # démarre sur http://localhost:5173, proxy /api vers localhost:8000
```

### Développement backend en local (hors conteneur)

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

## Variables d'environnement principales (`.env`)

| Variable | Rôle | Obligatoire |
|---|---|---|
| `JWT_SECRET` | Clé de signature des tokens JWT (min. 32 caractères aléatoires) | ✅ |
| `INGEST_API_KEY` | Clé requise sur les endpoints d'ingestion de logs | ✅ |
| `DATABASE_URL` | Connexion PostgreSQL/SQLite (comptes, alertes, audit, règles) | ✅ |
| `ELASTICSEARCH_URL` / `ELASTICSEARCH_PASSWORD` | Connexion au cluster de logs | ✅ |
| `RETENTION_DAYS` | Durée de rétention avant purge automatique | Non (défaut 30) |
| `RATE_LIMIT_MAX_REQUESTS` / `RATE_LIMIT_WINDOW_SECONDS` | Limitation de débit sur l'API | Non |
| `SMTP_HOST` / `SMTP_USER` / `SMTP_PASSWORD` / `ALERT_EMAIL_TO` | Notifications email réelles (playbook `escalate_admin`) | Non — sans ces valeurs, le canal email est simplement absent |
| `SLACK_WEBHOOK_URL` / `TEAMS_WEBHOOK_URL` | Notifications webhook réelles | Non — idem |
| `FIREWALL_API_URL` | URL du service `firewall-controller` réel (voir `infra/firewall-controller/`) pour le playbook `block_ip`. Par défaut `http://firewall-controller:8080` en Docker Compose | ✅ pour un `block_ip` opérationnel — sans cette valeur, il échoue explicitement (`status: "failure"`), jamais un faux succès |

## Tests essentiels

```bash
cd backend
python3 -m pytest tests/ -v                          # suite complète
python3 -m pytest tests/test_no_fake_data.py -v       # garde-fou anti-mock/anti-simulation
python3 -m pytest tests/unit/s3/ -v                   # MFA, SOAR, UEBA, exports, dashboard, health
```

```bash
cd frontend
npm run build          # vérifie la compilation (aucun test unitaire JS configuré à ce jour)
```

## Reproduction du projet à partir de zéro

1. `git clone` le dépôt et se placer à la racine.
2. `cp .env.example .env` puis renseigner les secrets marqués `[INSECURE-DEFAULT]`.
3. `bash infra/tls/generate-certs.sh` pour générer les certificats TLS auto-signés (nginx).
4. `docker compose up -d --build`.
5. Créer un compte administrateur initial (voir `docs/runbooks/`).
6. (Optionnel) Injecter le dataset de test 30 jours :
   `python3 dataset/generators/log_generator.py --ingest --backend-url http://localhost:8000 --api-key <INGEST_API_KEY>`
7. Lancer une corrélation manuelle pour vérifier la détection :
   `POST /api/correlation/run` avec `{"window_minutes": 43200}` pour couvrir les 30 jours.

## Structure du dépôt
| Dossier | Rôle |
|---|---|
| `backend/` | API REST, moteurs de corrélation, SOAR, RBAC, UEBA |
| `frontend/` | Interface React — dashboards, alertes, investigation |
| `agents/` | Collecteurs Syslog/Filebeat et normalisateurs |
| `infra/` | Docker, TLS, Elasticsearch, Nginx, monitoring, **service firewall réel** (`firewall-controller/`) |
| `docs/` | Architecture, CDC, rapports, API, schémas BDD |
| `dataset/` | Générateurs de logs et scénarios MITRE ATT&CK — **outils de test uniquement**, jamais utilisés comme source d'affichage par défaut du frontend |
| `tests/` | Tests unitaires, intégration et e2e |
| `scripts/` | Helpers CI/CD, seed, déploiement |

## État réel des fonctionnalités (honnête, sans données de démo)

Le frontend ne contient plus aucune donnée mock : toutes les vues sont branchées sur l'API backend réelle
et affichent un état "aucune donnée" / "backend indisponible" honnête en l'absence de données, plutôt que
d'inventer des graphiques ou des KPI.

### Pleinement fonctionnel (backend réel + persistance)
- Authentification locale + MFA TOTP (RFC 6238)
- RBAC (lecteur / analyste / administrateur)
- Alertes (listing, acquittement, résolution) — SQL réel
- Règles de corrélation (CRUD, activation/désactivation) — SQL réel
- Recherche de logs multi-critères (IP source, host, type, sévérité, plage horaire, mot-clé) — Elasticsearch réel
- **Export CSV/Excel des logs filtrés** (`POST /api/search/export.csv|.xlsx`) et **des alertes**
  (`GET /api/alerts/export.csv|.xlsx`, filtrage gravité/statut/période)
- SOAR : `disable_account` (réel, modifie la base utilisateurs), `escalate_admin` (email SMTP réel si configuré)
- UEBA : scores de risque et anomalies calculés et persistés réellement
- Rapports PDF hebdomadaires (agrégation Elasticsearch + SQL réelle)
- Audit trail (journal réel des actions utilisateurs)
- Gestion des utilisateurs (création, modification de rôle, suppression) — SQL réel
- **Dashboard** (`GET /api/dashboard`) : volume de logs/heure (agrégation `date_histogram` Elasticsearch sur 24h),
  top alertes actives (SQL), top IP sources (agrégation `terms` Elasticsearch)
- Investigation forensique : timeline réelle par entité (IP/host) depuis Elasticsearch, marquage persistant
- **Vues par profil** : Dashboard Analyste (technique), Vue RSSI (synthèse macro sans détail brut), Vue Auditeur
  (conformité/traçabilité/preuve d'intégrité, ex-`Compliance`)
- **Crisis Room** : rafraîchissement automatique réel toutes les 5 secondes (exigence CDC), sans requêtes concurrentes
- **Santé infrastructure** (`GET /api/system/health`) : vérification réelle du cluster Elasticsearch, sondes TCP
  réelles sur syslog-receiver/nginx, heartbeat indirect pour le forwarder (aucun port exposé)
- **Dataset de test 30 jours + 3 attaques cachées** (`dataset/generators/log_generator.py`) : brute-force SSH,
  mouvement latéral, exfiltration lente — vérifié détectable par le moteur de corrélation réel
- **SOAR `block_ip`** : appelle réellement le service `firewall-controller` (`infra/firewall-controller/`)
  qui exécute `iptables` via subprocess. Voir [`docs/security/firewall-controller.md`](docs/security/firewall-controller.md)
  pour le contrat HTTP, les permissions requises (`NET_ADMIN`) et les limites de portée du blocage.

### Fonctionnel mais dépendant d'une configuration externe absente
- **Notifications Slack/Teams** : nécessitent `SLACK_WEBHOOK_URL` / `TEAMS_WEBHOOK_URL`. Sans ces variables,
  le canal est simplement absent de `channels_notified`, sans erreur ni fausse confirmation.
- **Email SMTP** : fonctionnel si `SMTP_HOST`/`SMTP_USER`/`SMTP_PASSWORD`/`ALERT_EMAIL_TO` sont renseignés.

### Non implémenté (affiché honnêtement comme indisponible, jamais simulé)
- **Supervision des agents de collecte** (statut, version, redémarrage à distance) : aucun endpoint
  backend n'existe (`/api/agents` n'est pas implémenté). La vue `SystemConfig` l'indique explicitement au
  lieu d'afficher une liste d'agents fictifs.
- **Métriques serveur** (CPU/RAM/stockage) : aucun endpoint `/api/system/metrics` n'existe.
- **Scores de conformité ISO 27001 / RGPD chiffrés** : aucune évaluation de conformité réelle n'est
  implémentée côté backend. La vue `Compliance` affiche uniquement des comptages réels (incidents ouverts,
  événements liés aux données), sans pourcentage inventé.
- **Géolocalisation des IP sources** : aucun service de résolution IP → pays/ville n'existe côté backend ;
  le dashboard affiche à la place un classement réel des IP sources les plus actives.
- **Métriques CPU/RAM/stockage serveur** : `/api/system/health` vérifie la disponibilité réseau des services,
  pas leurs métriques de charge (aucun endpoint ne les fournit).
- **Cloisonnement organisationnel effectif** (équipe/service/filiale/environnement) : les champs existent sur
  le modèle `User` mais ne filtrent aucune donnée aujourd'hui — voir le rapport d'audit final pour le détail.

## Rapport d'audit sécurité final

Voir [`docs/rapports/S3/rapport-audit-securite-final.md`](docs/rapports/S3/rapport-audit-securite-final.md) —
état factuel de la posture sécurité, RGPD/ISO 27001, résultats de détection sur le dataset de test, et écarts
restants (non flatteur, chaque affirmation est reliée à une preuve technique vérifiable).
