# Brancher sa machine locale au SIEM (syslog réel)

Ce guide connecte les logs système de ta machine (rsyslog) au récepteur
syslog du SIEM (port 5140, UDP). Aucun agent tiers requis — rsyslog est déjà
présent et actif sur la machine.

---

## 1. Créer la règle de transfert rsyslog (sécurité uniquement)

> **Mise à jour** : la règle `*.*` (tout transférer) a été abandonnée après
> test réel — elle noie le SIEM sous du bruit applicatif local (ex: logs de
> debug PyCharm envoyés à syslog, ~10 000 événements sans intérêt sécurité en
> quelques minutes) et fausse le classement des IP sources actives. On ne
> transfère désormais que les facilities pertinentes pour un SIEM :
> authentification (`auth`, `authpriv`) et noyau (`kern`, utile pour détecter
> scans/anomalies réseau bas niveau).

```bash
sudo tee /etc/rsyslog.d/60-siem-forward.conf > /dev/null <<'CONF'
# Transfert des logs de sécurité pertinents vers le SIEM Smart SIEM
# (récepteur syslog UDP, port 5140 sur cette même machine hôte).
# Volontairement restreint à auth/authpriv/kern pour éviter le bruit
# applicatif local (ex: logs de debug d'IDE) qui noierait les vraies alertes.
auth,authpriv,kern.*  @127.0.0.1:5140
CONF
```

## 2. Redémarrer rsyslog

```bash
sudo systemctl restart rsyslog
sudo systemctl status rsyslog --no-pager | head -5
```

## 3. Vérifier que le SIEM tourne bien

```bash
cd "/home/ems/Documents/projet Integrateur"
docker ps --format "{{.Names}}\t{{.Status}}"
```

## 4. Générer un événement de test

```bash
logger -p auth.info "SIEM test depuis $(hostname)"
```

## 5. Vérifier côté SIEM que le log est arrivé

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin1234!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST "http://localhost:8000/api/search" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"SIEM test","page_size":5}' | python3 -m json.tool
```

Le log doit apparaître avec `host` = le nom de ta machine (`hostname`).

---

## 6. (Optionnel) Revenir en arrière

Pour arrêter l'envoi vers le SIEM :

```bash
sudo rm /etc/rsyslog.d/60-siem-forward.conf
sudo systemctl restart rsyslog
```

## 7. (Fait une fois, pour référence) Nettoyage du bruit déjà indexé

Si tu as déjà transféré du bruit applicatif avec l'ancienne règle `*.*`,
purge-le côté Elasticsearch (adapter le mot-clé au bruit constaté) :

```bash
docker exec siem-backend python3 -c "
from elasticsearch import Elasticsearch
from app.core.config import settings

es = Elasticsearch(hosts=[settings.elasticsearch_url])
resp = es.delete_by_query(
    index=settings.es_logs_index_name,
    body={'query': {'match': {'raw_message': 'pycharm'}}},
    conflicts='proceed',
)
print('supprimés:', resp.get('deleted', 0))
"
```
