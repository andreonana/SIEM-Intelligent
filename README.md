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
- **Backend** : Python (FastAPI)
- **Frontend** : React 19 + Vite + Tailwind CSS v4
- **BDD** : Elasticsearch (logs) + SQLite/PostgreSQL (comptes, alertes, audit, règles)
- **Agents** : Syslog (UDP/TCP) / Filebeat custom
- **Infra** : Docker / Docker Compose, reverse proxy nginx (TLS)

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
curl -k https://localhost/                 # frontend (build React réel) + API via nginx (443)
```

`https://localhost/` sert directement le build de production du frontend (voir
`docker-compose.yml`, service `nginx`, volume `./frontend/dist:/usr/share/nginx/html`)
et reverse-proxifie `/api/*` + `/health` vers le backend FastAPI. Le certificat est
auto-signé (`infra/certs/`) — le navigateur affichera un avertissement à accepter.

**Important** : ce volume ne se met à jour que si `frontend/dist/` existe déjà
(`cd frontend && npm run build`) avant de démarrer nginx, et le conteneur nginx
doit être **recréé** (pas juste redémarré) après toute modification de
`infra/nginx/nginx.conf` — un simple bind-mount de fichier unique ne suit pas
un remplacement atomique du fichier par un éditeur (nouvel inode) :
```bash
docker compose up -d --force-recreate nginx
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

## Tests

### Backend (pytest)

```bash
cd backend
pip install -r requirements-dev.txt   # inclut pytest, pytest-asyncio, httpx
python3 -m pytest tests/unit/ -v      # 157 tests (S1 à S3) — aucune régression connue
```

> Si tu exécutes les tests **dans le conteneur** `siem-backend` plutôt que sur
> l'hôte : le volume `siem_db:/app` masque le contenu de l'image à chaque
> démarrage (bind sur un volume nommé persistant, pas un mount du code source).
> Le dossier `tests/` n'y est donc pas présent par défaut — il faut le copier
> manuellement avant de lancer pytest :
> ```bash
> docker cp backend/tests siem-backend:/app/tests
> docker exec siem-backend pip install pytest pytest-asyncio httpx
> docker exec siem-backend python3 -m pytest tests/unit/ -v
> ```
> C'est une limitation connue de la config Docker actuelle (volume mal ciblé,
> devrait pointer uniquement sur le fichier `siem.db`) — à corriger dans une
> prochaine itération plutôt que contournée à chaque fois.

### Frontend (Vitest)

```bash
cd frontend
npm install
npm run build     # vérifie la compilation
npm run test      # Vitest — hook useSearch, LogExplorer, InvestigationView (18 tests)
```

## Reproduction du projet à partir de zéro

1. `git clone` le dépôt et se placer à la racine.
2. `cp .env.example .env` puis renseigner les secrets marqués `[INSECURE-DEFAULT]`.
3. `bash infra/tls/generate-certs.sh` pour générer les certificats TLS auto-signés (nginx).
4. `cd frontend && npm install && npm run build` pour produire `dist/` (servi par nginx).
5. `docker compose up -d --build`.
6. Créer un compte administrateur initial (voir `docs/runbooks/`).
7. (Optionnel) Injecter le dataset de test 30 jours :
   `python3 dataset/generators/log_generator.py --ingest --backend-url http://localhost:8000 --api-key <INGEST_API_KEY>`
8. Lancer une corrélation manuelle pour vérifier la détection :
   `POST /api/correlation/run` avec `{"window_minutes": 43200}` pour couvrir les 30 jours.
9. (Optionnel) Brancher une vraie machine (syslog réel) : voir
   [`docs/runbooks/brancher-machine-locale.md`](docs/runbooks/brancher-machine-locale.md)
   et [`docs/runbooks/restreindre-rsyslog.md`](docs/runbooks/restreindre-rsyslog.md)
   (limiter le transfert à `auth,authpriv` pour éviter tout bruit applicatif ou système).

## Structure du dépôt
| Dossier | Rôle |
|---|---|
| `backend/` | API REST, moteurs de corrélation, SOAR, RBAC, UEBA |
| `frontend/` | Interface React — dashboards, alertes, recherche, investigation |
| `agents/` | Collecteurs Syslog/Filebeat et normalisateurs |
| `infra/` | Docker, TLS, Elasticsearch, Nginx (reverse proxy + build statique), monitoring, **service firewall réel** (`firewall-controller/`) |
| `docs/` | Architecture, CDC, rapports, API, schémas BDD, diagrammes UML, runbooks |
| `dataset/` | Générateurs de logs et scénarios MITRE ATT&CK — **outils de test uniquement**, jamais utilisés comme source d'affichage par défaut du frontend |
| `scripts/` | Helpers CI/CD, seed, déploiement, simulation d'attaque live |

## Frontend — architecture et rôles

Une seule implémentation active : `frontend/src/views/` + `App.jsx` (routeur interne
par état, pas de react-router). Les dossiers `pages/`, hooks parallèles
(`useAlerts`, `useDashboard`...) et sous-composants (`components/{dashboard,alerts,
auth,common,ueba}`) issus d'un scaffold initial abandonné ont été retirés au fur et
à mesure qu'ils se révélaient être des doublons morts, jamais importés.

### Cloisonnement RBAC strict par interface

Chaque rôle a **sa propre interface**, sans recouvrement (sauf l'administrateur, qui
hérite de tout) — voir `frontend/src/config/navigation.js` :

| Rôle | Interface exclusive |
|---|---|
| `reader` | Vue Auditeur (conformité) uniquement |
| `analyst` | Dashboard technique + tout le poste opérationnel (logs, recherche, investigation, alertes, playbooks, UEBA, salle de crise, règles, rapports) |
| `administrator` | Vue RSSI + administration (utilisateurs, audit, config système) + héritage complet des deux autres |

### Recherche et investigation (S2 Data)

- **`views/LogExplorer.jsx.jsx`** — recherche multi-critères réelle (`POST /api/search`) : IP source, hôte, utilisateur/mot-clé, type de log, criticité, plage horaire. Résultats triés, horodatés, paginés — aucun filtrage local ne masque la source de vérité backend.
- **`views/InvestigationView.jsx`** — timeline forensique réelle (`GET /api/investigation/{entity_id}`), avec représentation visuelle proportionnelle au temps (`components/charts/TimelineChart.jsx`), liste chronologique cliquable (`components/investigation/ForensicTimeline.jsx`) et agrégation par sévérité/type/hôte (`components/investigation/PivotTable.jsx`).
- **Pivot** : depuis un résultat de recherche, "Investiguer cette IP"/"cet hôte" bascule vers la vue Investigation et charge automatiquement la chronologie. "Marquer suspect" persiste réellement (`POST /api/investigation/{entity_id}/flag`).
- **`hooks/useSearch.js`** — gère critères, pagination, chargement, erreurs et relance de recherche ; seul point d'accès à `POST /api/search` pour cette vue.

### UEBA — sélection du type d'entité

Le backend supporte l'analyse comportementale par `source_ip`, `host` ou `user`
(`POST /api/ueba/analyze`). La vue `UEBA.jsx` expose désormais un sélecteur pour les
trois — auparavant seul `source_ip` était jamais déclenché depuis l'interface, ce qui
empêchait tout hôte local d'apparaître dans les résultats.

## État réel des fonctionnalités (honnête, sans données de démo)

Le frontend ne contient plus aucune donnée mock : toutes les vues sont branchées sur l'API backend réelle
et affichent un état "aucune donnée" / "backend indisponible" honnête en l'absence de données, plutôt que
d'inventer des graphiques ou des KPI.

### Pleinement fonctionnel (backend réel + persistance)
- Authentification locale + MFA TOTP (RFC 6238)
- RBAC (lecteur / analyste / administrateur), cloisonnement d'interface strict (voir ci-dessus)
- Alertes (listing, acquittement, résolution) — SQL réel, y compris depuis les playbooks SOAR (persistance corrigée : exécuter une contre-mesure ou clôturer via le triage marque désormais réellement l'alerte `resolved`, elle ne réapparaissait pas correctement auparavant)
- Règles de corrélation (CRUD, activation/désactivation) — SQL réel
- Recherche de logs multi-critères (IP source, host, type, sévérité, plage horaire, mot-clé) — Elasticsearch réel, interface dédiée avec pagination
- **Export CSV/Excel des logs filtrés** (`POST /api/search/export.csv|.xlsx`) et **des alertes**
  (`GET /api/alerts/export.csv|.xlsx`, filtrage gravité/statut/période)
- SOAR : `block_ip` (réel, `firewall-controller`), `disable_account` (réel, modifie la base utilisateurs, nécessite une saisie manuelle du nom d'utilisateur car les alertes réseau n'en portent pas), `escalate_admin` (email SMTP réel si configuré)
- UEBA : scores de risque et anomalies calculés et persistés réellement, analysables par IP, hôte ou utilisateur
- Rapports PDF hebdomadaires (agrégation Elasticsearch + SQL réelle)
- Audit trail (journal réel des actions utilisateurs, y compris le **rôle** de l'acteur au moment de l'action)
- Gestion des utilisateurs (création, modification de rôle, suppression) — SQL réel. La "suppression" est une **désactivation logique** côté backend (compte conservé pour l'audit) ; l'interface le reflète honnêtement au lieu de prétendre à une suppression définitive.
- **Dashboard** (`GET /api/dashboard`) : volume de logs/heure (agrégation `date_histogram` Elasticsearch sur 24h),
  top alertes actives (SQL), top IP sources (agrégation `terms` Elasticsearch)
- Investigation forensique : timeline réelle par entité (IP/host) depuis Elasticsearch, marquage persistant, pivot depuis la recherche
- **Vues par profil** : Dashboard Analyste (technique), Vue RSSI (synthèse macro sans détail brut), Vue Auditeur
  (conformité/traçabilité/preuve d'intégrité)
- **Crisis Room** : rafraîchissement automatique réel toutes les 5 secondes (exigence CDC), sans requêtes concurrentes ; l'escalade manuelle depuis le triage des alertes y persiste correctement
- **Santé infrastructure** (`GET /api/system/health`) : vérification réelle du cluster Elasticsearch, sondes TCP
  réelles sur syslog-receiver/nginx, heartbeat indirect pour le forwarder (aucun port exposé)
- **Reverse proxy nginx réel** : TLS, redirection HTTP→HTTPS, sert le build frontend + proxifie l'API
- **Dataset de test 30 jours + 3 attaques cachées** (`dataset/generators/log_generator.py`) : brute-force SSH,
  mouvement latéral, exfiltration lente — vérifié détectable par le moteur de corrélation réel
- **SOAR `block_ip`** : appelle réellement le service `firewall-controller` (`infra/firewall-controller/`)
  qui exécute `iptables` via subprocess. Voir [`docs/security/firewall-controller.md`](docs/security/firewall-controller.md)
  pour le contrat HTTP, les permissions requises (`NET_ADMIN`) et les limites de portée du blocage.
- **Ingestion syslog réelle depuis une machine physique** : testé de bout en bout (rsyslog → UDP 5140 → normalisation → Elasticsearch → corrélation → alerte → blocage SOAR) — voir `docs/runbooks/brancher-machine-locale.md`.

### Fonctionnel mais dépendant d'une configuration externe absente
- **Notifications Slack/Teams** : nécessitent `SLACK_WEBHOOK_URL` / `TEAMS_WEBHOOK_URL`. Sans ces variables,
  le canal est simplement absent de `channels_notified`, sans erreur ni fausse confirmation.
- **Email SMTP** : fonctionnel si `SMTP_HOST`/`SMTP_USER`/`SMTP_PASSWORD`/`ALERT_EMAIL_TO` sont renseignés.

### Non implémenté (affiché honnêtement comme indisponible, jamais simulé)
- **Gestion de parc / inventaire de machines** : aucune interface pour "déclarer" ou "ajouter" une machine à
  surveiller — n'importe quelle source envoyant un log syslog apparaît automatiquement (conforme au CDC, qui
  ne demande qu'un agent déployable, pas un registre d'assets). Pas de contrôle d'accès par machine ni de
  vue "liste des machines surveillées".
- **Supervision des agents de collecte** (statut, version, redémarrage à distance) : aucun endpoint
  backend n'existe (`/api/agents` n'est pas implémenté). La vue `SystemConfig` l'indique explicitement au
  lieu d'afficher une liste d'agents fictifs.
- **Métriques serveur** (CPU/RAM/stockage) : aucun endpoint `/api/system/metrics` n'existe.
- **Scores de conformité ISO 27001 / RGPD chiffrés** : aucune évaluation de conformité réelle n'est
  implémentée côté backend. La vue Vue Auditeur affiche uniquement des comptages réels (incidents ouverts,
  événements liés aux données), sans pourcentage inventé.
- **Géolocalisation des IP sources** : aucun service de résolution IP → pays/ville n'existe côté backend ;
  le dashboard affiche à la place un classement réel des IP sources les plus actives.
- **Cloisonnement organisationnel effectif** (équipe/service/filiale/environnement) : les champs existent sur
  le modèle `User` mais ne filtrent aucune donnée aujourd'hui — voir le rapport d'audit final pour le détail.

## Limitations d'infrastructure connues

- **Volume backend (`siem_db:/app`)** : masque tout le répertoire applicatif de l'image au profit d'un
  volume nommé persistant. Toute modification du code source ne prend effet qu'après reconstruction de
  l'image **et** suppression/recréation du volume, ou copie manuelle (`docker cp`) dans le conteneur en
  cours d'exécution pour un test ponctuel. À corriger : ne monter que le fichier `siem.db`, pas `/app` entier.
- **Bind-mount de fichier unique (`nginx.conf`)** : un éditeur qui remplace le fichier par renommage atomique
  (nouvel inode) casse le bind-mount jusqu'à recréation du conteneur (`--force-recreate`), un simple `reload`
  ou `restart` ne suffit pas.
- **Règles rsyslog trop larges déconseillées** : `*.*` transfère tout le bruit applicatif local (ex. logs de
  debug d'IDE, ~10 000 événements en quelques minutes) et fausse les statistiques (classement IP sources, faux
  positifs `RULE_005` sur un simple redémarrage de rsyslog). La facility `kern` est **elle aussi déconseillée** :
  testée en conditions réelles, elle a généré **164 969 logs** de refus AppArmor (`operation="ptrace"`) en
  quelques heures sur une seule machine — bruit système répétitif sans valeur ici. Se limiter à `auth,authpriv.*`.
- **`RULE_005`** (détection d'arrêt du service de journalisation) fait un filtrage par mot-clé naïf
  (`"syslog"`, `"auditd"`...) sans distinguer un redémarrage normal d'une désactivation malveillante — connu
  comme générateur de faux positifs, non corrigé à ce jour.

## Rapport d'audit sécurité final

Voir [`docs/rapports/S3/rapport-audit-securite-final.md`](docs/rapports/S3/rapport-audit-securite-final.md) —
état factuel de la posture sécurité, RGPD/ISO 27001, résultats de détection sur le dataset de test, et écarts
restants (non flatteur, chaque affirmation est reliée à une preuve technique vérifiable).
