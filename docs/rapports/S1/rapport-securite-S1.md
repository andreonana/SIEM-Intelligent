# Rapport Sécurité — Semaine 1 (S1)
## Smart SIEM — Périmètre sécurité S1

**Date :** 2026-06-30  
**Périmètre :** Backend FastAPI + Infra Docker + Elasticsearch

---

## 1. Architecture sécurité S1

```
[Client]
   │ HTTPS (TLS 1.2/1.3)
   ▼
[Nginx — reverse proxy frontal]
   │ HTTP interne
   ▼
[Backend FastAPI :8000]
   ├── Auth JWT (HS256)
   ├── RBAC (reader / analyst / administrator)
   ├── Audit SQL (audit_logs)
   └── Rétention ES (purge + audit)
   │
   ▼
[SQLite / PostgreSQL] ←── utilisateurs + audit_logs
[Elasticsearch :9200] ←── logs + purge par rétention
```

---

## 2. Authentification locale

- **Mécanisme :** login/password → JWT signé HS256
- **Stockage mots de passe :** bcrypt (hash uniquement — aucun mot de passe en clair en base)
- **JWT :** signé avec `JWT_SECRET` (variable d'environnement obligatoire, longueur ≥ 32 caractères)
- **Durée de vie :** configurable via `JWT_EXPIRY_MINUTES` (défaut : 60 min)
- **Comptes inactifs :** refusés au login (`is_active=False`)
- **Complexité mot de passe :** 8+ caractères, majuscule, minuscule, chiffre, caractère spécial
- **Logout :** côté serveur : journalisation de l'action. Côté client : suppression du token (JWT non révocable avant expiration — limitation connue)

---

## 3. Modèle RBAC

### Rôles et niveaux

| Rôle          | Niveau | Accès                                               |
|---------------|--------|-----------------------------------------------------|
| `reader`      | 1      | Lecture des logs, alertes, dashboard                |
| `analyst`     | 2      | reader + gestion alertes, investigation, corrélation|
| `administrator` | 3    | analyst + gestion utilisateurs, audit, rétention    |

### Hiérarchie
Un rôle de niveau supérieur inclut tous les droits des niveaux inférieurs.

### Endpoints protégés S1

| Endpoint                        | Rôle minimum   |
|---------------------------------|----------------|
| `POST /api/auth/login`          | public         |
| `POST /api/auth/logout`         | reader         |
| `GET  /api/logs`                | reader         |
| `POST /api/logs`                | clé API statique (`X-API-Key`) |
| `GET  /api/users`               | administrator  |
| `POST /api/users`               | administrator  |
| `PUT  /api/users/{id}`          | administrator  |
| `DELETE /api/users/{id}`        | administrator  |
| `GET  /api/audit`               | administrator  |
| `POST /api/admin/retention/run` | administrator  |

---

## 4. Gestion des utilisateurs

- **Stockage :** base relationnelle persistante (SQLite développement / PostgreSQL production)
- **Modèle :** `id`, `username`, `hashed_password`, `role`, `is_active`, `team`, `service`, `subsidiary`, `environment`, `created_at`, `updated_at`
- **Opérations :** création, mise à jour (rôle, mot de passe, activation, périmètre), désactivation logique (soft delete)
- **Désactivation :** le compte reste en base (intégrité de l'audit) mais est refusé au login

### Comptes initiaux
Créés automatiquement au premier démarrage si la table est vide :

| Username  | Rôle            | Mot de passe initial |
|-----------|-----------------|----------------------|
| admin     | administrator   | Admin1234!           |
| analyst   | analyst         | Analyst1234!         |
| reader    | reader          | Reader1234!          |

**Action requise en production :** changer ces mots de passe immédiatement après le premier démarrage.

---

## 5. Audit de sécurité

- **Stockage :** table SQL `audit_logs` (persistante, indépendante d'Elasticsearch)
- **Accès :** réservé aux `administrator`
- **Filtres :** par `username` et par `action`
- **Pagination :** configurable (défaut 50 entrées par page)

### Actions auditées

| Action              | Déclencheur                          |
|---------------------|--------------------------------------|
| `login`             | Tentative de login (succès et échec) |
| `logout`            | Déconnexion                          |
| `create_user`       | Création d'un utilisateur            |
| `role_update`       | Changement de rôle                   |
| `disable_user`      | Désactivation d'un compte            |
| `retention_cleanup` | Purge de rétention (manuelle/auto)   |

---

## 6. Politique de rétention

- **Durée :** configurable via `RETENTION_DAYS` dans `.env` (défaut : 30 jours)
- **Périmètre :** index Elasticsearch `smart-siem-logs`
- **Déclenchement automatique :** scheduler APScheduler, purge quotidienne à 02h00 UTC
  - Désactivable via `ENABLE_RETENTION_SCHEDULER=false` (tests / CI)
- **Déclenchement manuel :** `POST /api/admin/retention/run` (administrator uniquement)
- **Audit :** chaque purge est enregistrée dans `audit_logs` (SQL), qu'elle réussisse ou non
- **Tolérance ES indisponible :** l'erreur ES est journalisée, l'audit SQL est écrit dans tous les cas

---

## 7. Chiffrement des communications (TLS)

### Architecture TLS activée

```
Client → HTTPS:443 → Nginx (TLS termination) → HTTP:8000 → Backend
```

- **Certificats :** auto-signés (CA SmartSIEM) générés dans `infra/certs/`
- **Script de génération :** `bash infra/tls/generate-certs.sh`
- **Protocoles acceptés :** TLS 1.2 et TLS 1.3
- **Ciphers :** `HIGH:!aNULL:!MD5`
- **Headers sécurité Nginx :** `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security`
- **Nginx :** activé dans `docker-compose.yml` (ports 80 et 443)
- **Redirection :** HTTP → HTTPS automatique

### Prérequis avant démarrage
```bash
bash infra/tls/generate-certs.sh
docker compose up -d
```

### Limitation connue
Les certificats sont auto-signés. Les clients (navigateurs, curl) doivent soit :
- accepter le certificat manuellement,
- ou utiliser le CA `infra/certs/ca.crt` comme autorité de confiance.

Pour la production, remplacer par des certificats Let's Encrypt ou émis par une CA d'entreprise.

---

## 8. Variables de configuration sensibles

| Variable                  | Valeur par défaut        | Sécurité             |
|---------------------------|--------------------------|----------------------|
| `JWT_SECRET`              | `dev-jwt-secret-...`     | ⚠️ À remplacer       |
| `INGEST_API_KEY`          | `dev-only-change-me`     | ⚠️ À remplacer       |
| `ELASTICSEARCH_PASSWORD`  | `changeme`               | ⚠️ À remplacer       |
| `DATABASE_URL`            | SQLite local             | OK dev / ⚠️ prod     |
| `RETENTION_DAYS`          | 30                       | OK                   |

**Génération de secrets sécurisés :**
```bash
# JWT_SECRET
python3 -c "import secrets; print(secrets.token_hex(32))"

# INGEST_API_KEY
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## 9. Procédures d'exploitation minimales

### Premier démarrage
```bash
# 1. Générer les certificats TLS
bash infra/tls/generate-certs.sh

# 2. Configurer les secrets dans .env
# (JWT_SECRET, INGEST_API_KEY, ELASTICSEARCH_PASSWORD)

# 3. Démarrer la stack
docker compose up -d

# 4. Changer les mots de passe des comptes initiaux
# Via PUT /api/users/{id} avec le token administrator
```

### Consulter l'audit
```bash
curl -H "Authorization: Bearer <token_admin>" https://localhost/api/audit
```

### Déclencher une purge de rétention manuelle
```bash
curl -X POST -H "Authorization: Bearer <token_admin>" https://localhost/api/admin/retention/run
```

---

## 10. Limites connues et recommandations pour S2/S3

| Limite                         | Recommandation S2+                                 |
|--------------------------------|----------------------------------------------------|
| JWT non révocable              | Liste noire Redis ou tokens de session             |
| SQLite en développement        | Migrer vers PostgreSQL en production               |
| Certificats auto-signés        | Let's Encrypt / CA d'entreprise                    |
| Rate limiting en mémoire       | Redis pour les déploiements multi-instances        |
| Pas de MFA                     | TOTP (Google Authenticator) en S2                 |
| Rotation des secrets manuelle  | Vault ou secrets manager en S3                    |
| Elasticsearch sans auth        | Activer xpack.security en production              |
