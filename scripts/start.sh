#!/usr/bin/env bash
# ============================================================
# Smart SIEM — Démarrage de la stack S1
# Usage : bash scripts/start.sh [--build] [--local]
#   --build : reconstruit les images Docker
#   --local : démarre uniquement le backend en local (sans Docker)
# ============================================================
set -e
cd "$(dirname "$0")/.."

MODE_BUILD=false
MODE_LOCAL=false
for arg in "$@"; do
  case $arg in
    --build) MODE_BUILD=true ;;
    --local) MODE_LOCAL=true ;;
  esac
done

echo "============================================"
echo "  Smart SIEM — Démarrage S1"
echo "============================================"

if [ "$MODE_LOCAL" = true ]; then
  echo "[start] Mode local (sans Docker)"
  echo "[start] Prérequis : Elasticsearch accessible sur http://localhost:9200"
  cd backend
  uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
  exit 0
fi

# Vérifier Docker
if ! command -v docker &>/dev/null; then
  echo "[start] ERREUR : Docker non trouvé. Installer Docker Desktop ou Docker Engine."
  exit 1
fi

echo "[start] Démarrage de la stack Docker Compose..."

if [ "$MODE_BUILD" = true ]; then
  docker compose build --no-cache
fi

docker compose up -d

echo ""
echo "[start] Attente que le backend soit disponible..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    echo "[start] Backend prêt ✓"
    break
  fi
  sleep 2
  echo "  ... attente ($i/30)"
done

echo ""
echo "============================================"
echo "  Stack démarrée ✓"
echo "============================================"
echo "  Backend     : http://localhost:8000"
echo "  API Docs    : http://localhost:8000/docs"
echo "  Health      : http://localhost:8000/health"
echo "  Elasticsearch : http://localhost:9200"
echo ""
echo "  Logs        : docker compose logs -f backend"
echo "  Arrêt       : docker compose down"
echo "============================================"
