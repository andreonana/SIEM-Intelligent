# Guide de démarrage et de simulation — Smart SIEM

Ce guide permet de relancer, tester et simuler l'intégralité du projet par toi-même,
avec toutes les commandes prêtes à copier-coller. Il part de l'état actuel : **tous
les conteneurs sont stoppés mais pas supprimés** — les données (logs, alertes, comptes,
règles) sont intactes dans les volumes Docker.

---

## 0. Prérequis

- Docker + Docker Compose (v2)
- `curl`, `python3` (pour lire les réponses JSON dans les exemples)
- Se placer à la racine du projet :
  ```bash
  cd "/home/ems/Documents/projet Integrateur"
  ```

---

## 1. Démarrer tous les services

Les images Docker existent déjà localement (construites lors des sessions
précédentes). **Ne pas utiliser `--build` sur `backend`, `forwarder` et
`syslog-receiver`** : leurs `Dockerfile` sont actuellement vides sur disque (dérive
connue, sans impact car les images sont déjà construites et fonctionnelles). Seul
`firewall-controller` a un Dockerfile réel et peut être reconstruit librement.

```bash
docker compose up -d --no-build
```

Cette commande relance les 6 services : `elasticsearch`, `backend`, `firewall-controller`,
`syslog-receiver`, `forwarder`, `nginx`.

### Vérifier que tout démarre (attendre ~30-60s pour Elasticsearch)

```bash
docker ps --format "{{.Names}}\t{{.Status}}"
```

Tu dois voir les 6 conteneurs `Up`. `elasticsearch` et `backend` doivent passer à
`(healthy)` après quelques dizaines de secondes.

### Vérifier la santé de chaque service individuellement

```bash
curl -s http://localhost:8000/health                    # backend
curl -s http://localhost:9200/_cluster/health            # elasticsearch
curl -s http://localhost:8080/health                     # firewall-controller
```

---

## 2. Se connecter

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin1234!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token obtenu : ${TOKEN:0:20}..."
```

Garde cette variable `$TOKEN` : toutes les commandes suivantes en dépendent (dans le
même terminal). Si le terminal est fermé, relance cette commande.

**Compte disponible** : `admin` / `Admin1234!` (rôle administrator). Deux autres
comptes existent (`analyst`, `reader`) mais leurs mots de passe ne sont pas connus —
voir section 9 pour en créer un nouveau si besoin.

---

## 3. Lancer le frontend (optionnel, pour l'interface graphique)

```bash
cd frontend
npm install       # une seule fois
npm run dev -- --port 5173 --host
```

Ouvre ensuite **http://localhost:5173** dans un navigateur et connecte-toi avec le
compte ci-dessus. Le proxy Vite redirige automatiquement `/api` vers le backend sur
le port 8000.

---

## 4. Simuler et vérifier les fonctionnalités une à une

### 4.1 Dashboard réel (agrégation Elasticsearch + SQL)

```bash
curl -s "http://localhost:8000/api/dashboard" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### 4.2 Rechercher des logs (multi-critères)

```bash
curl -s -X POST "http://localhost:8000/api/search" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"severity":"critical","page_size":10}' | python3 -m json.tool
```

### 4.3 Exporter des logs (CSV / Excel)

```bash
curl -s -X POST "http://localhost:8000/api/search/export.csv" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"page_size":100}' -o logs_export.csv
echo "Fichier généré : logs_export.csv"

curl -s -X POST "http://localhost:8000/api/search/export.xlsx" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"page_size":100}' -o logs_export.xlsx
echo "Fichier généré : logs_export.xlsx"
```

### 4.4 Lister et exporter les alertes

```bash
curl -s "http://localhost:8000/api/alerts?page_size=20" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

curl -s "http://localhost:8000/api/alerts/export.csv" -H "Authorization: Bearer $TOKEN" -o alerts_export.csv
```

### 4.5 Lancer une corrélation manuelle (détection sur les 30 derniers jours)

```bash
curl -s -X POST "http://localhost:8000/api/correlation/run" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"window_minutes": 43200}' | python3 -m json.tool
```

### 4.6 Déclencher un playbook SOAR réel — blocage d'IP

```bash
curl -s -X POST "http://localhost:8000/api/soar/playbooks/block_ip/run" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"params":{"ip":"203.0.113.50","reason":"test manuel"}}' | python3 -m json.tool

# Vérifier que la règle iptables est réellement posée :
docker exec siem-firewall-controller iptables -L INPUT -n | grep 203.0.113.50

# Débloquer :
curl -s -X DELETE "http://localhost:8080/block/203.0.113.50"
```

### 4.7 UEBA — scores de risque et anomalies

```bash
curl -s "http://localhost:8000/api/ueba/risk-scores" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
curl -s -X POST "http://localhost:8000/api/ueba/analyze" -H "Authorization: Bearer $TOKEN"
```

### 4.8 Investigation forensique (timeline par IP/host)

```bash
curl -s "http://localhost:8000/api/investigation/99.99.99.99" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Marquer une entité comme suspecte :
curl -s -X POST "http://localhost:8000/api/investigation/99.99.99.99/flag" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"note":"comportement suspect"}'
```

### 4.9 Rapport PDF hebdomadaire

```bash
curl -s "http://localhost:8000/api/reports/weekly?days=7" \
  -H "Authorization: Bearer $TOKEN" -o rapport-hebdo.pdf
echo "Rapport généré : rapport-hebdo.pdf"
```

### 4.10 Santé de l'infrastructure

```bash
curl -s "http://localhost:8000/api/system/health" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

## 5. Injecter le dataset de test (30 jours + 3 attaques cachées)

```bash
cd "/home/ems/Documents/projet Integrateur"
pip install httpx --break-system-packages   # si nécessaire

python3 dataset/generators/log_generator.py \
  --ingest \
  --backend-url http://localhost:8000 \
  --api-key dev-only-change-me
```

Ce script génère 30 jours de logs réalistes et injecte 3 attaques cachées
(brute-force SSH, mouvement latéral, exfiltration lente), puis les envoie
réellement au backend. Relance ensuite une corrélation (section 4.5) pour vérifier
qu'elles sont détectées :

```bash
curl -s "http://localhost:8000/api/alerts?page_size=100" -H "Authorization: Bearer $TOKEN" \
  | python3 -c "
import sys, json
from collections import Counter
d = json.load(sys.stdin)
print(Counter(a['rule_id'] for a in d['alerts']))
"
```

---

## 6. Lancer les tests automatisés

```bash
cd backend
python3 -m pytest tests/ -v                                 # suite complète
python3 -m pytest tests/test_no_fake_data.py -v              # garde-fou anti-simulation
python3 -m pytest tests/unit/s2/test_soar.py -v               # SOAR / block_ip
python3 -m pytest tests/unit/s3/ -v                            # MFA, UEBA, exports, dashboard, health

cd ../infra/firewall-controller
python3 -m pytest test_app.py -v                               # service firewall
```

```bash
cd frontend
npm run build          # vérifie la compilation du frontend
```

---

## 7. Consulter les rapports et la documentation

```bash
cat "docs/rapports/S3/rapport-audit-securite-final.md"     # audit sécurité factuel
cat "docs/security/firewall-controller.md"                  # doc du service firewall
cat README.md                                                # guide général du projet
```

---

## 8. Arrêter proprement

```bash
docker compose stop
# ou individuellement :
docker stop siem-backend siem-elasticsearch siem-firewall-controller siem-nginx siem-syslog-receiver siem-forwarder
```

Les données restent intactes (volumes non supprimés). Pour tout supprimer
définitivement (⚠️ irréversible, perte des logs/alertes/comptes) :

```bash
docker compose down -v
```

---

## 9. Créer un nouveau compte (si besoin d'un rôle analyst/reader)

```bash
curl -s -X POST "http://localhost:8000/api/users" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"TestPass1234!","role":"analyst"}' | python3 -m json.tool
```

---

## 10. Limitations connues (à garder en tête pendant la démo)

- `backend/Dockerfile` et `agents/Dockerfile` sont vides sur disque : ne jamais lancer
  `docker compose build backend` ou `--build` sans vérifier — utiliser les images déjà
  construites (`--no-build`).
- Le blocage `block_ip` n'agit que dans le network namespace du conteneur
  `firewall-controller`, pas sur l'hôte réel (voir `docs/security/firewall-controller.md`).
- `docker-compose.yml` référence des volumes/réseau externes déjà créés
  (`projetintegrateur_siem_db`, `projetintegrateur_es_data`, `projetintegrateur_siem-net`) :
  si tu repars d'un environnement totalement vierge, retire les lignes `external: true`
  dans `docker-compose.yml` pour laisser Compose les créer lui-même.
