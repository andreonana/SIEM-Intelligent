# Test UEBA E2E

Ce document permet de vérifier si le module UEBA fonctionne réellement de bout en bout
sur les logs actuellement présents dans le projet.

Chemin de travail :

```bash
cd /home/ems/Documents/projet\ Integrateur
```

---

## 1. Préparer un token admin

```bash
set +H
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin1234!"}' \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")
echo "$TOKEN"
```

---

## 2. Vérifier que les logs existent

```bash
curl -s "http://localhost:8000/api/v1/logs?page=1&page_size=5" \
  -H "Authorization: Bearer $TOKEN"
```

À vérifier dans la réponse :

- `source_ip`
- `host`
- `log_type`
- `raw_message`

---

## 3. Tester la baseline globale par `source_ip`

```bash
curl -s "http://localhost:8000/api/ueba/baseline?entity_type=source_ip&baseline_days=30" \
  -H "Authorization: Bearer $TOKEN"
```

À vérifier :

- `total > 0`
- présence de `usual_hours`
- présence de `usual_source_ips`
- présence de `usual_hosts`
- présence de `avg_daily_events`

---

## 4. Tester la baseline d’une IP précise

Exemple avec une IP déjà injectée :

```bash
curl -s "http://localhost:8000/api/ueba/baseline/source_ip/10.88.77.66?baseline_days=30" \
  -H "Authorization: Bearer $TOKEN"
```

Si tu obtiens `404`, cela peut vouloir dire :

- l’entité n’a pas assez d’historique ;
- la baseline ne l’a pas reconstruite ;
- l’UEBA lit mal les champs attendus.

---

## 5. Lancer une analyse UEBA

```bash
curl -s -X POST http://localhost:8000/api/ueba/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"entity_type":"source_ip","baseline_days":30,"window_minutes":180}'
```

À vérifier dans le retour :

- `entities_analyzed`
- `anomalies_detected`
- `alerts_created`

---

## 6. Lire les anomalies persistées

```bash
curl -s "http://localhost:8000/api/ueba/anomalies?entity_type=source_ip&page=1&page_size=20" \
  -H "Authorization: Bearer $TOKEN"
```

Tu dois voir :

- `anomaly_type`
- `severity`
- `weight`
- `description`
- `evidence`

---

## 7. Lire les scores de risque

```bash
curl -s "http://localhost:8000/api/ueba/risk-scores?entity_type=source_ip&page=1&page_size=20" \
  -H "Authorization: Bearer $TOKEN"
```

Tu dois voir :

- `score`
- `risk_level`
- `anomaly_count`
- `justification`

---

## 8. Vérifier une entité précise

```bash
curl -s "http://localhost:8000/api/ueba/entities/source_ip/10.88.77.66/risk" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 9. Vérifier si UEBA crée une alerte

```bash
curl -s http://localhost:8000/api/alerts \
  -H "Authorization: Bearer $TOKEN"
```

Chercher une alerte contenant :

- `rule_id: UEBA_HIGH_RISK`

---

## 10. Vérifier l’audit

```bash
curl -s http://localhost:8000/api/audit \
  -H "Authorization: Bearer $TOKEN"
```

Chercher :

- `action: ueba_analysis`

---

## 11. Injecter un log atypique pour tester UEBA

```bash
curl -X POST http://localhost:8000/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-only-change-me" \
  -d '{"raw_message":"<34>Jul 01 03:15:00 odd-srv sshd[999]: Failed password for root from 203.0.113.200 port 22","source":"syslog"}'
```

---

## 12. Relancer l’analyse UEBA après injection

```bash
curl -s -X POST http://localhost:8000/api/ueba/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"entity_type":"source_ip","baseline_days":30,"window_minutes":180}'
```

Puis relire les anomalies :

```bash
curl -s "http://localhost:8000/api/ueba/anomalies?entity_type=source_ip&page=1&page_size=20" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 13. Interprétation des résultats

### UEBA fonctionne réellement si :

- la baseline retourne des entités ;
- `analyze` retourne des entités analysées ;
- `anomalies_detected` est supérieur à 0 quand tu injectes un comportement atypique ;
- `risk-scores` contient des scores récents ;
- une alerte UEBA peut apparaître ;
- l’audit contient `ueba_analysis`.

### UEBA est seulement partiellement branché si :

- la baseline fonctionne ;
- mais `anomalies_detected` reste toujours à 0 ;
- ou `risk-scores` reste vide ;
- ou `source_ip` marche mais `user` ne marche pas.

### UEBA est probablement aveugle sur les vrais logs si :

- les logs existent bien dans `/api/v1/logs` ;
- mais la baseline ou les anomalies restent presque vides ;
- surtout si le moteur s’attend à `message`, `user`, `username`
  alors que les logs actuels contiennent surtout `raw_message`.

---

## 14. Vérification complémentaire sur `user`

```bash
curl -s "http://localhost:8000/api/ueba/baseline?entity_type=user&baseline_days=30" \
  -H "Authorization: Bearer $TOKEN"
```

Puis :

```bash
curl -s -X POST http://localhost:8000/api/ueba/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"entity_type":"user","baseline_days":30,"window_minutes":180}'
```

Si `user` ne donne rien alors que `source_ip` donne des résultats, cela signifie souvent que
les logs normalisés actuels ne portent pas assez d’informations `user/username`.

---

## Verdict attendu

Le module UEBA peut être considéré comme réellement opérationnel si :

- baseline OK ;
- analyse OK ;
- anomalies persistées ;
- scores persistés ;
- audit OK ;
- alertes UEBA possibles.

Si seule la baseline marche mais que les anomalies ne remontent jamais, il faut alors corriger
la lecture des champs réels des logs dans le moteur UEBA.
