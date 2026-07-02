#!/usr/bin/env bash
#
# scripts/security/simulate_live_attack.sh
#
# Simule une attaque RÉELLE en direct : envoie de vrais paquets syslog UDP au
# récepteur du SIEM (port 5140), exactement comme le ferait un serveur Linux
# compromis. Utilisable pendant une démonstration live pour montrer la
# détection en temps réel (ingestion → corrélation → alerte → SOAR).
#
# Usage :
#   ./simulate_live_attack.sh brute-force   [IP_ATTAQUANT] [HOST_CIBLE]
#   ./simulate_live_attack.sh lateral       [IP_INTERNE]
#   ./simulate_live_attack.sh exfiltration  [HOST_CIBLE]
#
# Prérequis : nc (netcat), le SIEM démarré (docker compose up -d).

set -euo pipefail

SYSLOG_HOST="${SYSLOG_HOST:-localhost}"
SYSLOG_PORT="${SYSLOG_PORT:-5140}"
BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"

send() {
    local msg="$1"
    # LC_TIME=C impose les abréviations de mois en anglais (Jul, Aug...),
    # requises par le parseur RFC3164 — sinon "juil." (locale FR) est rejeté.
    echo "<34>$(LC_TIME=C date '+%b %d %H:%M:%S') $msg" | nc -u -w1 "$SYSLOG_HOST" "$SYSLOG_PORT"
}

scenario="${1:-}"

case "$scenario" in
    brute-force)
        ATTACKER_IP="${2:-198.51.100.77}"
        TARGET_HOST="${3:-web-srv-live}"
        echo ">> Brute-force SSH en direct : ${ATTACKER_IP} -> ${TARGET_HOST} (12 tentatives)"
        for i in $(seq 1 12); do
            send "${TARGET_HOST} sshd[$((3000+i))]: Failed password for root from ${ATTACKER_IP} port $((40000+i)) ssh2"
            sleep 0.3
        done
        echo ">> Terminé. Les logs sont indexés en quelques secondes."
        ;;

    lateral)
        SOURCE_IP="${2:-10.0.4.201}"
        echo ">> Mouvement latéral en direct : ${SOURCE_IP} authentifie root sur 3 hôtes"
        for host in web-srv-live db-srv-live file-srv-live; do
            send "${host} sshd[5000]: Accepted publickey for root from ${SOURCE_IP} port 22 ssh2"
            sleep 0.5
        done
        echo ">> Terminé."
        ;;

    exfiltration)
        TARGET_HOST="${2:-file-srv-live}"
        echo ">> Exfiltration en direct depuis ${TARGET_HOST} (transferts fractionnés)"
        for i in $(seq 1 6); do
            bytes=$((10485760 + i * 2097152))
            send "${TARGET_HOST} netflow[6000]: Outbound transfer dest=198.51.100.23 port=443 bytes=${bytes} proto=HTTPS user=svc-backup"
            sleep 0.4
        done
        echo ">> Terminé."
        ;;

    *)
        echo "Usage : $0 {brute-force|lateral|exfiltration} [paramètres...]"
        exit 1
        ;;
esac

echo ""
echo ">> Pour déclencher la corrélation immédiatement (sans attendre le cycle automatique) :"
echo "   TOKEN=\$(curl -s -X POST ${BACKEND_URL}/api/auth/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"<mdp>\"}' | python3 -c \"import sys,json;print(json.load(sys.stdin)['access_token'])\")"
echo "   curl -s -X POST ${BACKEND_URL}/api/correlation/run -H \"Authorization: Bearer \$TOKEN\" -H 'Content-Type: application/json' -d '{\"window_minutes\": 10}'"
