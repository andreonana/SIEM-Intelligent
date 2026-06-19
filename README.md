# Smart SIEM — Plateforme de Gestion et d'Analyse des Événements de Sécurité

Projet étudiant (équipe de 5-6) — 3 semaines

## Modules fonctionnels
1. Collecte et normalisation des logs
2. Stockage, indexation et conservation
3. Corrélation d'événements (MITRE ATT&CK)
4. Alertes et réponse aux incidents (SOAR)
5. Visualisation et reporting
6. Recherche et investigation forensique
7. Gestion des utilisateurs et sécurité d'accès (RBAC/MFA)
8. Analyse comportementale UEBA

## Stack
- **Backend** : Python (FastAPI) / Node.js
- **Frontend** : React + Vite + Tailwind CSS
- **BDD** : Elasticsearch + PostgreSQL
- **Agents** : Syslog / Filebeat custom
- **Infra** : Docker / Docker Compose

## Démarrage rapide
```bash
cp .env.example .env
docker compose up -d
```

## Structure du dépôt
| Dossier | Rôle |
|---|---|
| `backend/` | API REST, moteurs de corrélation, SOAR, RBAC, UEBA |
| `frontend/` | Interface React — dashboards, alertes, investigation |
| `agents/` | Collecteurs Syslog/Filebeat et normalisateurs |
| `infra/` | Docker, TLS, Elasticsearch, Nginx, monitoring |
| `docs/` | Architecture, CDC, rapports, API, schémas BDD |
| `dataset/` | Générateurs de logs et scénarios MITRE ATT&CK |
| `tests/` | Tests unitaires, intégration et e2e |
| `scripts/` | Helpers CI/CD, seed, déploiement |
