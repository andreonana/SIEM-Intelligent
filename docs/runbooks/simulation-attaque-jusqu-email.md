# Simulation d'attaque en direct — de l'injection à la réception de l'email

Ce guide fournit toutes les commandes nécessaires pour dérouler une démonstration
complète et réelle : injection d'une attaque via syslog UDP → détection par le
moteur de corrélation → création d'alerte → déclenchement du playbook SOAR
`escalate_admin` → envoi réel d'un email SMTP → réception dans la boîte mail.

Aucune étape n'est simulée ou mockée : chaque commande déclenche un traitement
réel sur le backend, la base Elasticsearch/SQL, et le service SMTP configuré.

---

## 0. Prérequis

```bash
cd "/home/ems/Documents/projet Integrateur"
docker compose up -d --no-build
sleep 10
curl -s http://localhost:8000/health   # doit renvoyer {"status":"ok"}
```

Vérifier que la configuration SMTP est bien active dans le conteneur :

```bash
docker exec siem-backend python3 -c "from app.core.config import settings; print(settings.smtp_host, settings.alert_email_to)"
```

Si `SMTP_HOST` est vide, l'email ne sera jamais envoyé (comportement honnête,
pas de simulation) — renseigner `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`,
`ALERT_EMAIL_TO` dans `.env` puis relancer `docker compose up -d --no-build backend`.

---

## 1. S'authentifier et récupérer un token

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin1234!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token : ${TOKEN:0:20}..."
```

---

## 2. Injecter une attaque réelle (syslog UDP)

### Option A — via le script prêt à l'emploi

```bash
chmod +x scripts/security/simulate_live_attack.sh
./scripts/security/simulate_live_attack.sh brute-force 198.51.100.77 web-srv-demo
```

### Option B — commandes manuelles (si tu veux tout contrôler toi-même)

```bash
for i in $(seq 1 12); do
  echo "<34>$(LC_TIME=C date '+%b %d %H:%M:%S') web-srv-demo sshd[$((3000+i))]: Failed password for root from 198.51.100.77 port $((40000+i)) ssh2" \
    | nc -u -w1 localhost 5140
  sleep 0.3
done
```

> Important : `LC_TIME=C` force les abréviations de mois en anglais (`Jul`),
> requises par le parseur RFC3164. Sans cela, les logs sont rejetés si la
> locale système est en français (`juil.`).

Vérifier que les logs sont bien ingérés :

```bash
sleep 3
curl -s -X POST "http://localhost:8000/api/search" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source_ip":"198.51.100.77","page_size":20}' | python3 -m json.tool
```

---

## 3. Déclencher la corrélation (détection de l'attaque)

```bash
curl -s -X POST "http://localhost:8000/api/correlation/run" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"window_minutes": 10}' | python3 -m json.tool
```

Réponse attendue : `alerts_created` > 0. Vérifier l'alerte créée :

```bash
curl -s "http://localhost:8000/api/alerts?page_size=50" -H "Authorization: Bearer $TOKEN" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
for a in d['alerts']:
    if a.get('source_ip') == '198.51.100.77':
        print(a['id'], a['rule_id'], a['severity'], '-', a['description'])
"
```

Note l'`id` numérique de l'alerte affichée (ex. `42`) — il sert à l'étape suivante.

---

## 4. Déclencher l'escalade admin (playbook SOAR → email réel)

Remplacer `<ALERT_ID>` par l'id récupéré à l'étape 3 :

```bash
curl -s -X POST "http://localhost:8000/api/soar/playbooks/escalate_admin/run" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"params": {"reason": "Brute force détecté depuis 198.51.100.77 — 12 tentatives", "severity": "HIGH", "alert_id": <ALERT_ID>}}' \
  | python3 -m json.tool
```

Réponse attendue :
```json
{
  "result": {
    "status": "escalated",
    "channels_notified": ["email"]
  }
}
```

Si `channels_notified` est vide, c'est honnête : aucun canal n'est configuré
(vérifier `SMTP_HOST`/`SLACK_WEBHOOK_URL`/`TEAMS_WEBHOOK_URL` dans `.env`).

---

## 5. Vérifier la réception de l'email

Ouvrir la boîte mail configurée dans `ALERT_EMAIL_TO` (`.env`). Le message
reçu contient :
- Sujet : `[SIEM ESCALADE] HIGH — Action admin requise`
- Corps : raison, ID d'alerte, déclencheur

### Vérification alternative sans accès boîte mail (test direct SMTP)

```bash
docker exec siem-backend python3 -c "
import asyncio
from app.modules.alerting.notifier import send_email

async def test():
    ok = await send_email(
        'emsgoueth@gmail.com',
        '[SIEM] Test de démonstration',
        'Email envoyé réellement via SMTP depuis le backend Smart SIEM.'
    )
    print('Email envoyé :', ok)

asyncio.run(test())
"
```

`Email envoyé : True` confirme l'envoi réel (pas de simulation).

---

## 6. (Optionnel) Bloquer réellement l'IP attaquante

```bash
curl -s -X POST "http://localhost:8000/api/soar/playbooks/block_ip/run" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"params": {"ip": "198.51.100.77", "reason": "brute force confirmé"}}' | python3 -m json.tool

# Vérifier la règle iptables réellement posée :
docker exec siem-firewall-controller iptables -L INPUT -n | grep 198.51.100.77
```

---

## 7. Séquence complète en une seule fois (copier-coller)

```bash
cd "/home/ems/Documents/projet Integrateur"

TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin1234!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

./scripts/security/simulate_live_attack.sh brute-force 198.51.100.77 web-srv-demo
sleep 3

curl -s -X POST "http://localhost:8000/api/correlation/run" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"window_minutes": 10}' | python3 -m json.tool

ALERT_ID=$(curl -s "http://localhost:8000/api/alerts?page_size=50" -H "Authorization: Bearer $TOKEN" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
for a in d['alerts']:
    if a.get('source_ip') == '198.51.100.77':
        print(a['id']); break
")
echo "Alerte créée : ID=$ALERT_ID"

curl -s -X POST "http://localhost:8000/api/soar/playbooks/escalate_admin/run" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"params\": {\"reason\": \"Brute force détecté depuis 198.51.100.77\", \"severity\": \"HIGH\", \"alert_id\": $ALERT_ID}}" \
  | python3 -m json.tool

echo "Vérifie ta boîte mail : $ALERT_EMAIL_TO"
```

---

## Résumé du parcours réel

```
nc UDP:5140 → syslog-receiver → POST /api/v1/logs/ingest/bulk → Elasticsearch
    → POST /api/correlation/run → moteur de corrélation → Alert (SQL)
    → POST /api/soar/playbooks/escalate_admin/run → send_email() → aiosmtplib
    → smtp.gmail.com:587 (STARTTLS) → boîte mail réelle
```

Aucune étape de cette chaîne n'est mockée : chaque flèche correspond à un
appel réseau réel vers un service réellement démarré.
