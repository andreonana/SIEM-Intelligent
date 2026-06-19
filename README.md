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

## Organisation des branches

### Convention de nommage

Les branches suivent le schéma `<poste>/<semaine>` :

| Poste | S1 | S2 | S3 |
|---|---|---|---|
| Chef de projet | `chef-projet/S1` | `chef-projet/S2` | `chef-projet/S3` |
| Développeur Backend | `backend/S1` | `backend/S2` | `backend/S3` |
| Développeur Frontend | `frontend/S1` | `frontend/S2` | `frontend/S3` |
| Ingénieur Infrastructure | `infrastructure/S1` | `infrastructure/S2` | `infrastructure/S3` |
| Ingénieur Data | `data/S1` | `data/S2` | `data/S3` |
| Ingénieur DevOps | `devops/S1` | `devops/S2` | `devops/S3` |

### Pourquoi cette structuration ?

**Isolation par poste** — chaque membre travaille dans sa propre branche sans risquer d'écraser le travail d'un autre. Les conflits de fusion sont détectés et résolus consciemment lors des PR, pas par surprise.

**Isolation par semaine** — une branche par semaine crée un point de livraison clair à chaque fin de sprint. `S1` se ferme par une PR vers `main` avant que `S2` ne commence, ce qui donne un historique lisible : on peut retrouver exactement ce qui a été produit chaque semaine par chaque rôle.

**Traçabilité et revue de code** — toute modification passe par une Pull Request. Le chef de projet (ou un pair) valide avant que le code n'intègre `main`, ce qui évite d'introduire du code cassé dans la base commune.

**Parallélisme sans blocage** — les 6 membres travaillent simultanément sur leurs branches respectives. Il n'y a pas de verrou : le backend et le frontend avancent en même temps sans attendre l'autre.

### Flux de travail

```
main  ←─── PR fin de semaine ───  backend/S1
                                   frontend/S1
                                   infrastructure/S1
                                   ...
```

1. Cloner le dépôt et se positionner sur sa branche : `git checkout backend/S1`
2. Travailler, committer régulièrement
3. En fin de semaine : ouvrir une Pull Request vers `main`
4. Après merge : passer sur la branche suivante : `git checkout backend/S2`

---

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
