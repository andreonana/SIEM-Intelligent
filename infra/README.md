# SMART SIEM — Infrastructure Semaine 1

> Agent de collecte de logs multi-OS — Guide complet

| | |
|---|---|
| **Projet** | SMART SIEM — UCAC-ICAM |
| **Module** | Infrastructure — Semaine 1 |
| **Version** | 1.0.0 |
| **Stack** | Docker · Filebeat · Python · Flask · FastAPI |
| **OS supportés** | Windows (Docker Desktop) · Linux |

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Structure des fichiers](#2-structure-des-fichiers)
3. [Prérequis](#3-prérequis)
4. [Installation et démarrage](#4-installation-et-démarrage)
5. [Fonctionnement détaillé du pipeline](#5-fonctionnement-détaillé-du-pipeline)
6. [Configuration par OS](#6-configuration-par-os)
7. [Déploiement sur les machines des collaborateurs](#7-déploiement-sur-les-machines-des-collaborateurs)
8. [Connexion au vrai backend](#8-connexion-au-vrai-backend)
9. [Endpoints de la Mock API](#9-endpoints-de-la-mock-api)
10. [Commandes utiles](#10-commandes-utiles)
11. [Diagnostic des problèmes fréquents](#11-diagnostic-des-problèmes-fréquents)
12. [Sécurité — périmètre infra S1](#12-sécurité--périmètre-infra-s1)

---

## 1. Vue d'ensemble

Ce module constitue la couche de collecte du SIEM SMART. Son rôle est de surveiller les fichiers de logs des machines des collaborateurs, de normaliser chaque événement dans un format JSON standardisé, et de les transmettre par lot à l'API REST du backend central.

L'ensemble du pipeline tourne dans des conteneurs Docker orchestrés par Docker Compose, ce qui garantit un déploiement identique sur Windows et Linux sans aucune installation manuelle de dépendances.

### 1.1 Architecture générale

```
Fichier .log (hôte)
       │
       │  bind mount :ro
       ▼
  ┌─────────────┐      volume Docker nommé      ┌──────────────┐      POST HTTP(S)      ┌─────────────┐
  │  Filebeat   │ ─────────────────────────────▶│  Forwarder   │ ─────────────────────▶│  API REST   │
  │  (Docker)   │     filebeat-output (ndjson)  │  (Docker)    │                       │  (Backend)  │
  └─────────────┘                               └──────────────┘                       └─────────────┘
```

| Service | Image / Langage | Rôle |
|---|---|---|
| `filebeat` | Filebeat 8.13.0 (Elastic) | Surveille les fichiers `.log`, lit chaque nouvelle ligne, sérialise en JSON et écrit dans le volume partagé |
| `forwarder` | Python 3.11 (custom) | Tail le volume partagé, normalise chaque événement au format SIEM, envoie par batch vers l'API REST |
| `mock-api` | Flask — Python 3.11 | Simule le backend REST pendant les tests. Reçoit et stocke les logs en mémoire, expose `GET /api/logs` |

---

## 2. Structure des fichiers

```
SIEM-Intelligent/
├── docker-compose.yml           # Orchestration complète (dev local)
├── docker-compose.agent.yml     # Agent seul (déploiement machine distante)
├── .env                         # Variables d'environnement — ignoré par Git
├── .env.example                 # Modèle à copier pour les collaborateurs
├── .gitignore
└── infra/
    ├── filebeat/
    │   └── filebeat.yml         # Configuration Filebeat
    ├── forwarder/
    │   ├── Dockerfile
    │   ├── forwarder.py         # Normalisation multi-OS et envoi HTTP
    │   └── requirements.txt     # requests==2.31.0
    ├── mock_Api/
    │   ├── Dockerfile
    │   └── app.py               # API Flask de simulation
    └── log_test/
        └── test.log             # Fichier de logs pour les tests locaux
```

---

## 3. Prérequis

### Sur Windows

- Docker Desktop installé et démarré (icône dans la barre des tâches)
- WSL2 activé — Docker Desktop le demande automatiquement à l'installation
- Git installé
- Port `8000` libre sur la machine

### Sur Linux

- Docker Engine installé
- Docker Compose v2 installé (`docker compose`, pas `docker-compose`)
- Git installé
- Port `8000` libre

**Vérification rapide :**

```powershell
docker --version
docker compose version
```

---

## 4. Installation et démarrage

### 4.1 Cloner le dépôt

```bash
git clone <url-du-depot>
cd SIEM-Intelligent
```

### 4.2 Créer le fichier `.env`

Le fichier `.env` n'est jamais commité dans Git. Chaque collaborateur doit le créer depuis le modèle :

```bash
# Windows PowerShell
Copy-Item .env.example .env

# Linux / macOS
cp .env.example .env
```

Contenu par défaut pour un test local avec la Mock API :

```env
API_URL=http://mock-api:8000/api/logs
API_KEY=dev-key-temporaire
BATCH_SIZE=50
POLL_INTERVAL=5
```

| Variable | Valeur par défaut | Description |
|---|---|---|
| `API_URL` | `http://mock-api:8000/api/logs` | Endpoint de réception des logs. Changer pour l'IP du backend en production |
| `API_KEY` | `dev-key-temporaire` | Clé envoyée dans le header `X-API-Key`. À aligner avec le backend |
| `BATCH_SIZE` | `50` | Nombre d'événements par requête POST |
| `POLL_INTERVAL` | `5` | Secondes entre deux cycles de lecture du volume |

### 4.3 Lancer tous les services (dev local)

```bash
docker compose up --build -d
```

Docker effectue automatiquement :

1. Téléchargement de l'image Filebeat 8.13.0 depuis Docker Hub (127 MB, une seule fois)
2. Construction de l'image du Forwarder depuis `infra/forwarder/Dockerfile`
3. Construction de l'image de la Mock API depuis `infra/mock_Api/Dockerfile`
4. Création des volumes Docker nommés `filebeat-output` et `forwarder-state`
5. Démarrage dans l'ordre : `mock-api` → `filebeat` → `forwarder`

### 4.4 Vérifier le démarrage

```bash
docker compose ps
```

Les 3 services doivent afficher le statut `running`. En cas de problème :

```bash
docker compose logs filebeat
docker compose logs forwarder
docker compose logs mock-api
```

---

## 5. Fonctionnement détaillé du pipeline

### 5.1 Filebeat — lecture des fichiers de logs

Filebeat surveille le chemin `/logs-watched/*.log` à l'intérieur de son conteneur. Ce chemin est relié au dossier de la machine hôte via un **bind mount en lecture seule** (`:ro`) déclaré dans `docker-compose.yml`. Dès qu'une nouvelle ligne apparaît dans un fichier `.log`, Filebeat la lit et l'écrit dans le volume Docker nommé `filebeat-output` au format JSON lines (`.ndjson`).

Points importants :

- Filebeat maintient un **registry interne** qui mémorise sa position dans chaque fichier — après un redémarrage, il reprend exactement là où il s'était arrêté sans relire les lignes déjà traitées
- Le flag `-strict.perms=false` est obligatoire sur Windows car NTFS attribue des permissions `rwxrwxrwx` que Filebeat refuse par défaut
- La rotation automatique crée un nouveau fichier `.ndjson` tous les 10 Mo et conserve 5 fichiers maximum
- L'intervalle d'écriture par défaut est de **1 seconde maximum**

### 5.2 Volume partagé — couplage découplé

Le volume Docker nommé `filebeat-output` est le point de jonction entre Filebeat et le Forwarder. Filebeat y écrit en lecture-écriture, le Forwarder le monte en lecture seule (`:ro`).

> ⚠️ **Point critique** : Les deux services doivent référencer exactement le même nom de volume nommé (`filebeat-output`) dans `docker-compose.yml`. Un bind mount Windows dans le Forwarder au lieu du volume nommé les isole complètement et brise le pipeline — c'est le problème le plus fréquent lors du déploiement.

### 5.3 Forwarder — normalisation et envoi

Le Forwarder est un script Python qui tourne en boucle avec l'intervalle défini par `POLL_INTERVAL`. À chaque cycle :

1. Liste tous les fichiers `beats-output*` dans `/output` via glob
2. Compare la taille actuelle de chaque fichier à l'offset sauvegardé dans `/state/offset.json`
3. Lit les nouvelles lignes depuis l'offset, parse chaque ligne JSON
4. Détecte automatiquement le type de source (Linux syslog, Windows Event Log, Cisco IOS, Fortinet, Palo Alto, Check Point)
5. Construit l'événement normalisé via `build_event()` selon le format SIEM cible
6. Regroupe les événements par batch de taille `BATCH_SIZE`
7. Envoie chaque batch via `POST HTTP(S)` avec le header `X-API-Key`
8. En cas d'erreur réseau ou 5xx : retry avec backoff exponentiel (5 tentatives max, délais 1s/2s/4s/8s/16s)
9. Sauvegarde l'offset immédiatement après chaque batch confirmé — **zéro doublon, zéro perte**

### 5.4 Format JSON normalisé

```json
{
  "timestamp":   "2026-06-23T06:55:22Z",
  "source_ip":   "192.168.1.100",
  "host":        "nom-machine",
  "log_type":    "ssh",
  "severity":    "WARNING",
  "raw_message": "Failed password for root from 192.168.1.100 port 22",
  "tags":        ["ssh", "brute-force"],
  "source_type": "linux_syslog",
  "os":          "linux"
}
```

### 5.5 Sources de logs supportées

| Type source | Exemple de ligne | Champs enrichis |
|---|---|---|
| `linux_syslog` | `Jan 15 10:00:01 server sshd[1234]: Failed password...` | `process`, `log_type` via `LINUX_PROC_MAP` |
| `windows_event` | `Event ID: 4625 — An account failed to log on` | `event_id`, `provider` — 18 Event IDs mappés |
| `cisco_ios` | `%SEC-6-IPACCESSLOGP: list 101 denied tcp...` | `facility`, `mnemonic`, sévérité Cisco 0-7 |
| `fortinet` | `devname=FGT logid=0001 action=deny srcip=...` | `action`, `dst_ip`, `log_id` |
| `palo_alto` | CSV PAN-OS avec champs action/src/dst | `action` depuis champ 29 du CSV |
| `checkpoint` | `src=10.0.0.1 action=drop product=VPN...` | `action`, `product` |
| `generic` | Tout autre format | Extraction IP par regex, sévérité par mots-clés |

---

## 6. Configuration par OS

### 6.1 Linux — Filebeat en Docker

Sur Linux, les logs système sont des fichiers dans `/var/log/`. Filebeat y accède depuis son conteneur via un bind mount.

> ⚠️ Sans le bind mount déclaré dans `docker-compose.yml`, le conteneur est **aveugle** aux fichiers de la machine hôte.

Dans `docker-compose.yml`, remplacer le dossier de test par `/var/log` :

```yaml
filebeat:
  volumes:
    - /var/log:/logs-watched:ro    # logs réels de la machine Linux hôte
```

Fichiers surveillés typiques :

| Fichier | Contenu |
|---|---|
| `/var/log/auth.log` | Connexions SSH, sudo, authentifications (Debian/Ubuntu) |
| `/var/log/secure` | Même contenu sur CentOS/RHEL |
| `/var/log/syslog` | Logs système généraux |
| `/var/log/kern.log` | Noyau et pare-feu UFW |
| `/var/log/nginx/*.log` | Logs web Nginx |
| `/var/log/apache2/*.log` | Logs web Apache |

### 6.2 Windows — Filebeat natif + Forwarder Docker

Sur Windows, les logs système (Security, System, Application) sont dans l'**Event Log Windows** — un journal binaire accessible uniquement via l'API Win32 native. Un conteneur Docker sur Windows tourne dans Linux via WSL2 et **ne peut pas** appeler cette API.

**Solution** : installer Filebeat directement sur Windows comme service natif avec l'input `winlog`, et garder le Forwarder en Docker.

#### Installation de Filebeat natif sur Windows

1. Télécharger Filebeat pour Windows sur https://www.elastic.co/downloads/beats/filebeat
2. Extraire dans `C:\filebeat\`
3. Créer `C:\filebeat\filebeat.yml` :

```yaml
filebeat.inputs:
  - type: winlog
    event_logs:
      - name: Security        # Event IDs 4624/4625/4740 etc.
        ignore_older: 72h
      - name: System
        ignore_older: 72h
      - name: Application
        ignore_older: 72h

output.file:
  path: C:\filebeat\output
  filename: beats-output
  rotate_every_kb: 10240
  number_of_files: 5
```

4. Lancer comme service Windows (PowerShell en administrateur) :

```powershell
cd C:\filebeat
.\install-service-filebeat.ps1
Start-Service filebeat
```

Dans `docker-compose.agent.yml`, le Forwarder lit la sortie de Filebeat natif :

```yaml
forwarder:
  volumes:
    - C:\filebeat\output:/output:ro   # sortie du Filebeat natif Windows
    - forwarder-state:/state
```

---

## 7. Déploiement sur les machines des collaborateurs

### 7.1 Architecture de déploiement

En production, le backend tourne sur un **serveur central Linux**. Chaque machine collaborateur fait tourner uniquement l'agent et envoie ses logs vers l'IP du serveur.

```
Machine Windows/Linux (collaborateur A)  ──┐
Machine Windows/Linux (collaborateur B)  ──┤──▶  Serveur Linux central
Machine Windows/Linux (collaborateur C)  ──┘     (API REST + Base de données)
```

L'agent lit les logs locaux et les pousse. Le serveur reçoit et stocke. Jamais l'inverse.

### 7.2 Sur le serveur central Linux

Lancer uniquement le backend. Avec la mock-API de test :

```bash
docker compose up -d mock-api
```

En production avec le vrai backend FastAPI :

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

> ⚠️ **Important** : Le serveur doit écouter sur `0.0.0.0` (toutes les interfaces), **pas** `127.0.0.1` (loopback uniquement). Avec `127.0.0.1`, aucune machine extérieure ne peut se connecter même sur le même réseau WiFi.

### 7.3 Sur chaque machine collaborateur

1. **Cloner le dépôt**

```bash
git clone <url-repo>
cd SIEM-Intelligent
```

2. **Créer le `.env` avec l'IP du serveur central**

```bash
cp .env.example .env
```

```env
API_URL=http://192.168.1.XXX:8000/api/logs   # IP du serveur Linux
API_KEY=dev-key-temporaire
BATCH_SIZE=50
POLL_INTERVAL=5
```

3. **Lancer uniquement l'agent**

```bash
docker compose -f docker-compose.agent.yml up --build -d
```

4. **Vérifier que les logs partent**

```bash
docker compose -f docker-compose.agent.yml logs -f forwarder
```

Tu dois voir des lignes `[BATCH] X logs reçus | total=Y`.

---

## 8. Connexion au vrai backend

Quand le dev backend est disponible, la transition ne touche que le fichier `.env` — aucun code à modifier.

### 8.1 Récupérer sa branche Git

```bash
git fetch origin
git branch -r                                        # lister les branches distantes
git checkout -b test/backend origin/backend/semaine1
```

### 8.2 Trouver son endpoint

FastAPI génère une documentation interactive automatique. Ouvrir dans le navigateur :

```
http://<IP-backend>:8000/docs
```

Cette page liste tous les endpoints disponibles avec leur format de requête attendu.

### 8.3 Mettre à jour le `.env`

```env
API_URL=http://192.168.1.XXX:8000/<endpoint-exact>
API_KEY=<cle-fournie-par-le-backend>
```

### 8.4 Redémarrer le Forwarder

```bash
docker compose restart forwarder
docker compose logs -f forwarder
```

> ✅ **Si le format JSON doit changer** : seule la fonction `build_event()` dans `infra/forwarder/forwarder.py` est à modifier. Le reste du pipeline reste intact.

---

## 9. Endpoints de la Mock API

| Méthode | Endpoint | Description |
|---|---|---|
| `POST` | `/api/logs` | Reçoit un batch de logs. Header requis : `X-API-Key: <valeur>`. Body : JSON avec tableau `events[]` |
| `GET` | `/api/logs` | Retourne tous les logs reçus + statistiques (total, errors, warnings, info, batches) |
| `GET` | `/health` | Vérifie que l'API est opérationnelle. Retourne `{"status": "ok"}` |

**Exemple de body pour un test Postman (`POST /api/logs`) :**

```json
{
  "events": [
    {
      "timestamp": "2026-06-23T10:00:00Z",
      "source_ip": "192.168.1.100",
      "host": "test-machine",
      "log_type": "ssh",
      "severity": "WARNING",
      "raw_message": "Failed password for root from 192.168.1.100 port 22",
      "tags": ["ssh", "brute-force"]
    }
  ]
}
```

> ⚠️ La Mock API stocke les logs en RAM. Un redémarrage du conteneur `mock-api` efface tout.

---

## 10. Commandes utiles

### Gestion des services

| Commande | Action |
|---|---|
| `docker compose up -d` | Démarrer tous les services en arrière-plan |
| `docker compose up --build -d` | Reconstruire les images et démarrer |
| `docker compose down` | Arrêter et supprimer les conteneurs (volumes conservés) |
| `docker compose down -v` | Reset complet : conteneurs + volumes supprimés |
| `docker compose restart filebeat` | Redémarrer Filebeat seul |
| `docker compose restart forwarder` | Redémarrer le Forwarder seul (après modif `.env`) |
| `docker compose ps` | Voir l'état de tous les conteneurs |

### Logs et debug

| Commande | Action |
|---|---|
| `docker compose logs -f forwarder` | Suivre les envois du forwarder en temps réel |
| `docker compose logs -f filebeat` | Voir ce que Filebeat lit et écrit |
| `docker compose logs mock-api` | Voir les requêtes reçues par la mock-API |
| `docker compose exec filebeat ls /output` | Vérifier les fichiers dans le volume partagé (côté Filebeat) |
| `docker compose exec forwarder ls /output` | Vérifier le même volume côté Forwarder (doit être identique) |
| `docker compose exec filebeat ls /logs-watched` | Vérifier que les fichiers `.log` sont bien montés |

### Tests rapides

Injecter un log SSH (Windows PowerShell) :

```powershell
Add-Content .\infra\log_test\test.log "Jan 15 10:00:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 22"
```

Injecter un log Cisco :

```powershell
Add-Content .\infra\log_test\test.log "%SEC-6-IPACCESSLOGP: list 101 denied tcp 10.0.0.5 -> 192.168.1.1"
```

Injecter un log Fortinet :

```powershell
Add-Content .\infra\log_test\test.log 'devname=FGT logid=0001 action=deny srcip=10.0.0.50 dstip=8.8.8.8'
```

Consulter les logs reçus :

```powershell
# Navigateur
http://localhost:8000/api/logs

# PowerShell
Invoke-RestMethod -Uri "http://localhost:8000/api/logs" -Method GET
```

---

## 11. Diagnostic des problèmes fréquents

| Symptôme | Solution |
|---|---|
| Filebeat : `open_files: 0` | Le dossier de logs n'est pas monté. Vérifier : `docker compose exec filebeat ls /logs-watched` |
| Filebeat : `permissions error` | Vérifier que `command: filebeat -e -strict.perms=false` est présent dans `docker-compose.yml` |
| Filebeat : `Error decoding JSON` | Supprimer les lignes `json.keys_under_root` de `filebeat.yml` — les fichiers `.log` sont du texte brut, pas du JSON |
| Forwarder voit `/output` vide | Les volumes ne sont pas partagés. Vérifier que les deux services utilisent `filebeat-output` (volume nommé), pas un bind mount Windows |
| `docker compose down -v` ne supprime pas tout | Faire `docker volume prune -f` pour supprimer les volumes orphelins |
| `Connection refused` vers le backend | Le backend écoute sur `127.0.0.1` au lieu de `0.0.0.0`. Relancer avec `--host 0.0.0.0` |
| API retourne `401 Unauthorized` | Le header `X-API-Key` ne correspond pas à `API_KEY` dans `.env`. Vérifier les deux valeurs |
| Logs dupliqués après redémarrage | Faire `docker compose down -v` pour reset complet des volumes et de l'offset |
| Pull EOF / image tronquée | Coupure réseau pendant le téléchargement. Relancer `docker pull <image>` seul, puis `docker compose up --build -d` |

---

## 12. Sécurité — périmètre infra S1

La sécurité relevant de l'infra pour la Semaine 1 couvre le chiffrement des communications et la gestion des secrets. Le RBAC, la rétention et la journalisation des accès sont du ressort du backend.

| Exigence | Statut | Détail |
|---|---|---|
| Authentification API (`X-API-Key`) | ✅ En place | Header `X-API-Key` vérifié à chaque requête `POST` dans la Mock API et le Forwarder |
| Secrets hors du code | ✅ En place | `.env` ignoré par Git via `.gitignore`. Secrets passés par variables d'environnement Docker |
| Volumes en lecture seule | ✅ En place | Bind mounts logs montés en `:ro`. Volume partagé monté en `:ro` côté Forwarder |
| TLS sur les communications | ⚠️ Partiel | Implémenté avec certificat auto-signé pour la Mock API. À activer sur le vrai backend avec le dev |
| RBAC | ➡️ Backend | Hors périmètre infra S1 — à implémenter par le dev backend |
| Politique de rétention | ➡️ Backend | Hors périmètre infra S1 — à définir avec le data engineer |

---

*README généré le 28/06/2026 — SMART SIEM Infrastructure Semaine 1*