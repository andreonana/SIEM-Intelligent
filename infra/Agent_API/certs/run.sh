#!/usr/bin/env bash
# Lance l'AgentAPI en HTTP simple, à partir des variables d'environnement.
# Usage: source .env && ./run.sh   (ou via systemd, voir README.md)
set -euo pipefail
cd "$(dirname "$0")/.."

: "${AGENTAPI_TOKEN:?AGENTAPI_TOKEN manquant}"
: "${AGENTAPI_ALLOWED_CALLERS:?AGENTAPI_ALLOWED_CALLERS manquant}"

exec python3 -m uvicorn main:app \
  --host "${AGENTAPI_HOST:-0.0.0.0}" \
  --port "${AGENTAPI_PORT:-9000}"
