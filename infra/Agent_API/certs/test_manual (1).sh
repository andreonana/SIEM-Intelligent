#!/usr/bin/env bash
# Tests manuels de l'AgentAPI en HTTP simple.
# Lancer le serveur d'abord dans un autre terminal :
#   ./run.sh
# Ce script suppose AGENTAPI_ALLOWED_CALLERS contient 127.0.0.1 pour les tests locaux.
set -euo pipefail

TOKEN="${AGENTAPI_TOKEN:?Définir AGENTAPI_TOKEN dans l'environnement}"
BASE="http://127.0.0.1:9000"

curl -s "$BASE/health"; echo

echo -e "\n== Block sans token (doit échouer 401) =="
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$BASE/block" \
  -H "Content-Type: application/json" \
  -d '{"attacker_ip":"203.0.113.10","incident_id":"test-1","reason":"test"}'

echo -e "\n== Block avec token, IP invalide (doit échouer 422) =="
curl -s -X POST "$BASE/block" \
  -H "Content-Type: application/json" -H "X-API-Key: $TOKEN" \
  -d '{"attacker_ip":"not-an-ip","incident_id":"test-2","reason":"test"}'
echo

echo -e "\n== Block attaquant + victime en mode CONFIRM =="
curl -s -X POST "$BASE/block" \
  -H "Content-Type: application/json" -H "X-API-Key: $TOKEN" \
  -d '{
        "attacker_ip": "203.0.113.10",
        "victim_ip": "127.0.0.1",
        "victim_mode": "confirm",
        "incident_id": "test-3",
        "rule_id": "T1110-bruteforce-ssh",
        "reason": "5 echecs SSH en 60s"
      }'
echo

echo -e "\n== Status =="
curl -s "$BASE/status" -H "X-API-Key: $TOKEN"
echo

echo -e "\n== Audit =="
curl -s "$BASE/audit?limit=10" -H "X-API-Key: $TOKEN"
echo

echo -e "\n== Unblock de l'attaquant =="
curl -s -X POST "$BASE/unblock" \
  -H "Content-Type: application/json" -H "X-API-Key: $TOKEN" \
  -d '{"ip":"203.0.113.10","incident_id":"test-3","reason":"fin de test"}'
echo
