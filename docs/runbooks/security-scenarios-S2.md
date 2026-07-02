# Runbook — Scénarios de sécurité S2

**Date :** 2026-06-30  
**Objectif :** Commandes exactes pour simuler et tester chaque scénario d'attaque S2

---

## Pré-requis

```bash
# 1. Backend démarré (depuis le dossier backend/)
cd /home/ems/Documents/projet\ Integrateur/backend
uvicorn app.main:app --reload

# 2. Récupérer un token admin
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin1234!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token: $TOKEN"
```

---

## Scénario 1 — Reconnaissance (T1595, T1046)

```bash
# Simuler 22 logs de scan de ports et accès URLs sensibles
python3 /home/ems/Documents/projet\ Integrateur/scripts/security/simulate_attack.py \
  --scenario 1 \
  --url http://localhost:8000 \
  --api-key dev-only-change-me

# Vérifier les alertes générées
curl -s http://localhost:8000/api/v1/alerts \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Résultat attendu : alerte RULE_001 HIGH depuis 203.0.113.42
```

---

## Scénario 2 — Mouvement latéral (T1021, T1110)

```bash
# Simuler 24 logs SSH brute-force depuis 10.10.0.99 sur 4 hôtes
python3 /home/ems/Documents/projet\ Integrateur/scripts/security/simulate_attack.py \
  --scenario 2 \
  --url http://localhost:8000

# Alertes attendues :
# - RULE_001 HIGH (brute force par hôte — 4 alertes)
# - RULE_004 CRITICAL (même IP sur 4 hôtes distincts)
curl -s "http://localhost:8000/api/v1/alerts?severity=HIGH" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

curl -s "http://localhost:8000/api/v1/alerts?severity=CRITICAL" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

## Scénario 3 — Exfiltration (T1041)

```bash
# Simuler 16 logs d'exfiltration (outbound, exfil keywords)
python3 /home/ems/Documents/projet\ Integrateur/scripts/security/simulate_attack.py \
  --scenario 3 \
  --url http://localhost:8000

# Alerte attendue : RULE_004 CRITICAL depuis 192.168.1.77
curl -s "http://localhost:8000/api/v1/alerts?severity=CRITICAL" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

## Tous les scénarios d'un coup

```bash
python3 /home/ems/Documents/projet\ Integrateur/scripts/security/simulate_attack.py \
  --scenario all \
  --url http://localhost:8000
```

---

## Tests SOAR — Playbooks

```bash
# block_ip (simulation sans FIREWALL_API_URL)
curl -s -X POST http://localhost:8000/api/soar/playbooks/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"playbook_id":"block_ip","params":{"ip":"10.10.0.99","reason":"brute force","alert_id":1}}'

# disable_account
curl -s -X POST http://localhost:8000/api/soar/playbooks/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"playbook_id":"disable_account","params":{"username":"analyst","reason":"compromis","alert_id":2}}'

# escalate_admin
curl -s -X POST http://localhost:8000/api/soar/playbooks/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"playbook_id":"escalate_admin","params":{"reason":"Exfiltration detectee","alert_id":3,"severity":"CRITICAL"}}'
```

---

## Tests RBAC

```bash
# Token absent → 401
curl -v http://localhost:8000/api/v1/alerts
# Attendu : HTTP 401

# Token invalide → 401
curl -v http://localhost:8000/api/v1/alerts \
  -H "Authorization: Bearer invalid.token.here"
# Attendu : HTTP 401

# Rôle insuffisant (reader tente de créer un user) → 403
TOKEN_READER=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"reader","password":"Reader1234!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -v -X POST http://localhost:8000/api/users \
  -H "Authorization: Bearer $TOKEN_READER" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"Test1234!","role":"reader"}'
# Attendu : HTTP 403
```

---

## Audit trail

```bash
# Lister les événements audités
curl -s http://localhost:8000/api/v1/audit \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Filtrer par action
curl -s "http://localhost:8000/api/v1/audit?action=login" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

curl -s "http://localhost:8000/api/v1/audit?action=correlation_run" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

## Suite de tests automatisés

```bash
cd /home/ems/Documents/projet\ Integrateur/backend

# Tous les tests
python3 -m pytest tests/ -q --tb=short

# Tests de sécurité uniquement
python3 -m pytest tests/security/ -v

# Tests unitaires S2 (corrélation, SOAR, alertes)
python3 -m pytest tests/unit/s2/ -v

# Test RBAC spécifique
python3 -m pytest tests/unit/s2/test_alerts.py::test_rbac_reader_cannot_acknowledge -v
```

---

## Purge de rétention manuelle

```bash
curl -s -X POST http://localhost:8000/api/admin/retention/run \
  -H "Authorization: Bearer $TOKEN"
# Attendu : {"status": "purge terminée", "deleted": N, "cutoff": "...", ...}
```
