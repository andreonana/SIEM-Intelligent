# Firewall Controller — Intégration réelle du playbook SOAR `block_ip`

## 1. Ce qu'est `FIREWALL_API_URL`

`FIREWALL_API_URL` est l'URL du service firewall réel consommé par le playbook SOAR
`block_ip` (`backend/app/modules/soar/playbooks.py`). Ce n'est **plus une variable
optionnelle activant un mode simulé** : sans elle, `block_ip` échoue explicitement
(`status: "failure"`) au lieu de prétendre avoir bloqué une IP.

En Docker Compose, le service cible est `firewall-controller` (voir
`infra/firewall-controller/`), résolu via le DNS interne du réseau `siem-net` :

```
FIREWALL_API_URL=http://firewall-controller:8080
```

En développement local (hors Docker), pointez vers l'instance locale du service :

```
FIREWALL_API_URL=http://localhost:8080
```

## 2. Contrat HTTP attendu

Le backend s'attend à ce que le service firewall expose :

```
POST {FIREWALL_API_URL}/block
Content-Type: application/json

{"ip": "10.10.10.10", "reason": "brute force"}
```

**Réponse succès** (HTTP 200) :
```json
{"status": "blocked", "ip": "10.10.10.10"}
```

**Réponse échec** (HTTP 200 — l'échec est une donnée métier, pas une erreur de transport) :
```json
{"status": "failure", "ip": "10.10.10.10", "error": "message d'erreur explicite"}
```

Important : le backend **lit réellement ce corps de réponse** (`resp.json()`), il ne se
contente jamais du code HTTP. Un HTTP 200 avec `status: "failure"` dans le corps est bien
traité comme un échec par `_run_block_ip` — corrigé lors de cette intégration (l'ancienne
implémentation faisait aveuglément confiance à `resp.raise_for_status()` sans vérifier le
contenu réel de la réponse).

## 3. Le service `firewall-controller`

Implémentation réelle : `infra/firewall-controller/app.py` (FastAPI). Il expose :

| Route | Rôle |
|---|---|
| `POST /block` | Bloque réellement une IP via `iptables -I INPUT -s <ip> -j DROP` |
| `DELETE /block/{ip}` | Retire la règle (`iptables -D ...`) — utile en tests/démo |
| `GET /blocked` | Liste les IP bloquées par ce contrôleur depuis son démarrage |
| `GET /health` | Vérifie que la commande `iptables` est exécutable dans ce conteneur |

Aucune route n'est fictive : chaque appel à `/block` exécute réellement `iptables` via
`subprocess.run`, avec validation stricte de l'IP (module `ipaddress`) pour éliminer tout
risque d'injection de commande.

### Portée réelle du blocage

Ce contrôleur applique la règle `iptables` dans **son propre network namespace** (celui du
conteneur `firewall-controller`), pas sur l'hôte Docker ni sur les autres conteneurs de la
stack. C'est un blocage réel et vérifiable de bout en bout (la règle apparaît dans
`iptables -L`, un second appel sur la même IP est idempotent), mais il ne protège que ce
conteneur — pas l'infrastructure hôte. Pour un blocage qui affecterait réellement le trafic
entrant vers les autres services (ex : `syslog-receiver`), il faudrait exécuter ce
contrôleur avec `network_mode: host` et un accès privilégié à l'hôte Docker, ce qui a été
délibérément écarté ici pour rester démontrable sans exiger un accès root à la machine
hôte du projet.

### Permissions requises

Le conteneur nécessite la capability Linux `NET_ADMIN` (et `NET_RAW`) pour qu'`iptables`
puisse modifier les règles de filtrage — déclarée dans `docker-compose.yml` :

```yaml
firewall-controller:
  cap_add:
    - NET_ADMIN
    - NET_RAW
```

**Sans cette capability**, `iptables` échoue avec `Permission denied`. Le service ne masque
jamais cette erreur : elle est renvoyée telle quelle dans le champ `"error"` de la réponse
JSON, et propagée par le backend jusqu'à l'analyste (`status: "failure"`).

## 4. Démarrer le service

```bash
docker compose up -d --build firewall-controller
curl http://localhost:8080/health
```

## 5. Tester `block_ip` de bout en bout

```bash
# 1. Authentification
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<mot de passe>"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 2. Déclenchement réel du playbook
curl -X POST http://localhost:8000/api/soar/playbooks/block_ip/run \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"params":{"ip":"203.0.113.99","reason":"brute force détecté"}}'
# → {"result": {"status": "blocked", "ip": "203.0.113.99"}}

# 3. Vérification de la règle réelle dans le conteneur firewall
docker exec siem-firewall-controller iptables -L INPUT -n | grep 203.0.113.99
```

Test du cas d'échec (config absente) :
```bash
# Retirer temporairement FIREWALL_API_URL puis relancer le backend
# → {"result": {"status": "failure", "ip": "...", "error": "FIREWALL_API_URL non configuré..."}}
```

## 6. Limites connues

- Le blocage n'est effectif que dans le network namespace du conteneur `firewall-controller`
  (voir section 3) — ce n'est pas un pare-feu de périmètre protégeant l'hôte ou les autres
  services de la stack.
- Le registre des IP bloquées (`GET /blocked`) est en mémoire : il est réinitialisé à chaque
  redémarrage du conteneur, tout comme les règles `iptables` elles-mêmes (aucun volume
  persistant n'est utilisé).
- `NET_ADMIN`/`NET_RAW` sont des capabilities Linux privilégiées : en environnement
  restreint (ex. certains clusters Kubernetes managés, certaines plateformes de CI), leur
  attribution peut être refusée par la politique de sécurité de la plateforme — dans ce
  cas, `/health` retourne `iptables_available: false` et `/block` retourne honnêtement
  `status: "failure"`.
