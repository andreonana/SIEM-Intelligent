# Tests Projet Actuel

Ces commandes permettent de retester manuellement les flux déjà vérifiés sur la stack locale.

Répertoire de travail :

```bash
cd /home/ems/Documents/projet\ Integrateur
```

## 1. Vérifier la stack

```bash
docker compose ps
```

## 2. Envoyer un log direct au backend

```bash
curl -X POST http://localhost:8000/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-only-change-me" \
  -d '{"raw_message":"<34>Jun 30 12:34:56 test-srv sshd[999]: Failed password for root from 10.123.45.67 port 22","source":"syslog"}'
```

## 3. Vérifier ce log dans Elasticsearch

```bash
curl -X GET "http://localhost:9200/smart-siem-logs/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "match_phrase": {
        "raw_message": "Failed password for root from 10.123.45.67"
      }
    }
  }'
```

## 4. Tester le forwarder fichier

Ajouter une ligne dans le dossier surveillé :

```bash
echo '<34>Jun 30 15:10:00 file-srv sshd[1234]: Failed password for admin from 10.55.66.77 port 22' >> /home/ems/Documents/projet\ Integrateur/infra/log_test/generated.log
```

Vérifier les envois côté backend :

```bash
docker compose logs --tail=100 backend
```

Rechercher dans Elasticsearch :

```bash
curl -X GET "http://localhost:9200/smart-siem-logs/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "match_phrase": {
        "raw_message": "Failed password for admin from 10.55.66.77"
      }
    }
  }'
```

## 5. Tester syslog UDP via syslog-receiver

```bash
docker compose exec backend python -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'<34>Jun 30 15:22:00 udp-srv sshd[2201]: Failed password for root from 10.88.77.66 port 22\n', ('syslog-receiver', 5140)); print('udp_sent')"
```

## 6. Tester syslog TCP via syslog-receiver

```bash
docker compose exec backend python -c "import socket; s=socket.create_connection(('syslog-receiver', 5140), timeout=5); s.sendall(b'<34>Jun 30 15:23:00 tcp-srv sshd[2202]: Failed password for root from 10.88.77.67 port 22\n'); s.close(); print('tcp_sent')"
```

## 7. Vérifier le traitement syslog-receiver

```bash
docker compose logs --tail=80 syslog-receiver
```

Tu dois voir une ligne de ce type :

```text
batch envoyé : 2 OK, 0 erreurs
```

## 8. Vérifier les logs UDP/TCP dans Elasticsearch

UDP :

```bash
curl -X GET "http://localhost:9200/smart-siem-logs/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "match_phrase": {
        "raw_message": "10.88.77.66"
      }
    }
  }'
```

TCP :

```bash
curl -X GET "http://localhost:9200/smart-siem-logs/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "match_phrase": {
        "raw_message": "10.88.77.67"
      }
    }
  }'
```

## 9. Tester HTTPS via nginx dans Docker

```bash
docker compose exec backend python -c "import ssl, urllib.request; ctx=ssl._create_unverified_context(); r=urllib.request.urlopen('https://nginx/health', context=ctx, timeout=10); print(r.status); print(r.read().decode())"
```

Résultat attendu :

```text
200
{"status":"ok"}
```

## 10. Récupérer un token admin

```bash
TOKEN=$(docker compose exec backend python -c "import json, urllib.request; req=urllib.request.Request('http://backend:8000/api/auth/login', data=json.dumps({'username':'admin','password':'Admin1234!'}).encode(), headers={'Content-Type':'application/json'}, method='POST'); print(json.loads(urllib.request.urlopen(req).read().decode())['access_token'])" | tail -n 1)
```

Vérifier :

```bash
echo "$TOKEN"
```

## 11. Voir les règles S2

```bash
docker compose exec backend python -c "import os, urllib.request; req=urllib.request.Request('http://backend:8000/api/rules', headers={'Authorization': f'Bearer {os.environ[\"TOKEN\"]}'}); print(urllib.request.urlopen(req).read().decode())"
```

## 12. Lancer la corrélation S2

```bash
docker compose exec backend python -c "import json, os, urllib.request; req=urllib.request.Request('http://backend:8000/api/correlation/run', data=json.dumps({'window_minutes':180}).encode(), headers={'Authorization': f'Bearer {os.environ[\"TOKEN\"]}', 'Content-Type':'application/json'}, method='POST'); print(urllib.request.urlopen(req).read().decode())"
```

Point important :

Si la réponse contient `logs_analyzed: 0`, la corrélation est encore bugguée même si les logs sont bien stockés dans Elasticsearch.

## 13. Voir les alertes

```bash
docker compose exec backend python -c "import os, urllib.request; req=urllib.request.Request('http://backend:8000/api/alerts', headers={'Authorization': f'Bearer {os.environ[\"TOKEN\"]}'}); print(urllib.request.urlopen(req).read().decode())"
```

## 14. Voir les playbooks SOAR

```bash
docker compose exec backend python -c "import os, urllib.request; req=urllib.request.Request('http://backend:8000/api/soar/playbooks', headers={'Authorization': f'Bearer {os.environ[\"TOKEN\"]}'}); print(urllib.request.urlopen(req).read().decode())"
```

## 15. Exécuter `block_ip`

```bash
docker compose exec backend python -c "import json, os, urllib.request; payload={'params': {'ip': '10.88.77.66', 'reason': 'test manual'}}; req=urllib.request.Request('http://backend:8000/api/soar/playbooks/block_ip/run', data=json.dumps(payload).encode(), headers={'Authorization': f'Bearer {os.environ[\"TOKEN\"]}', 'Content-Type':'application/json'}, method='POST'); print(urllib.request.urlopen(req).read().decode())"
```

## 16. Exécuter `disable_account`

```bash
docker compose exec backend python -c "import json, os, urllib.request; payload={'params': {'username': 'reader', 'reason': 'test manual'}}; req=urllib.request.Request('http://backend:8000/api/soar/playbooks/disable_account/run', data=json.dumps(payload).encode(), headers={'Authorization': f'Bearer {os.environ[\"TOKEN\"]}', 'Content-Type':'application/json'}, method='POST'); print(urllib.request.urlopen(req).read().decode())"
```

## 17. Vérifier que `reader` est désactivé

```bash
docker compose exec backend python -c "import os, urllib.request; req=urllib.request.Request('http://backend:8000/api/users', headers={'Authorization': f'Bearer {os.environ[\"TOKEN\"]}'}); print(urllib.request.urlopen(req).read().decode())"
```

Tu dois voir `reader` avec :

```text
"is_active": false
```

## 18. Exécuter `escalate_admin`

```bash
docker compose exec backend python -c "import json, os, urllib.request; payload={'params': {'reason': 'test escalation', 'severity': 'CRITICAL'}}; req=urllib.request.Request('http://backend:8000/api/soar/playbooks/escalate_admin/run', data=json.dumps(payload).encode(), headers={'Authorization': f'Bearer {os.environ[\"TOKEN\"]}', 'Content-Type':'application/json'}, method='POST'); print(urllib.request.urlopen(req).read().decode())"
```

## 19. Vérifier l’audit

```bash
docker compose exec backend python -c "import os, urllib.request; req=urllib.request.Request('http://backend:8000/api/audit', headers={'Authorization': f'Bearer {os.environ[\"TOKEN\"]}'}); print(urllib.request.urlopen(req).read().decode())"
```

## Résumé attendu

- `API -> backend -> Elasticsearch` : doit marcher
- `fichier -> forwarder -> backend -> Elasticsearch` : doit marcher
- `syslog UDP/TCP -> syslog-receiver -> backend -> Elasticsearch` : doit marcher
- `HTTPS via nginx` : doit répondre dans Docker
- `SOAR` : doit marcher avec le format `{"params": {...}}`
- `corrélation` : l’endpoint répond, mais peut encore retourner `logs_analyzed: 0`
