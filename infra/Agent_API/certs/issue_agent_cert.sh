#!/usr/bin/env bash
# TLS n'est plus utilisé pour l'AgentAPI localement.
# Ce script est conservé comme no-op pour éviter de casser les anciens
# workflows, mais il n'est plus nécessaire pour démarrer l'API.
set -euo pipefail

echo "TLS n'est plus utilisé pour l'AgentAPI."
echo "Le service fonctionne en HTTP simple."
