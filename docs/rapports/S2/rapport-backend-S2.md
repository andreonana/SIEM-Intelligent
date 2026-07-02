# Rapport Backend S2 — Smart SIEM

## 1. Règles de corrélation actives

| Rule ID  | Nom                                        | Type      | Seuil | Fenêtre | Sévérité | MITRE Tactic         | MITRE Tech | SOAR Action    |
|----------|--------------------------------------------|-----------|-------|---------|----------|----------------------|------------|----------------|
| RULE_001 | Brute Force SSH/Auth                       | threshold | 5     | 10 min  | HIGH     | Credential Access    | T1110      | block_ip       |
| RULE_002 | Connexion hors horaires                    | pattern   | —     | 10 min  | WARNING  | Initial Access       | T1078      | —              |
| RULE_003 | Élévation de privilèges / modif. rôle     | pattern   | —     | 10 min  | HIGH     | Privilege Escalation | T1548      | escalate_admin |
| RULE_004 | Communication IP suspecte / exfiltration   | pattern   | —     | 10 min  | CRITICAL | Exfiltration         | T1041      | block_ip       |
| RULE_005 | Arrêt du service de logs / dissimulation   | pattern   | —     | 10 min  | CRITICAL | Defense Evasion      | T1562      | escalate_admin |

Les règles sont seedées en SQL au démarrage via `seed_correlation_rules()`.  
Les activer/désactiver via `PUT /api/rules/{rule_id}` (champ `enabled`).

## 2. Endpoints S2

### Alertes (`/api/alerts`)

| Méthode | Endpoint                          | Rôle minimum | Description                           |
|---------|-----------------------------------|--------------|---------------------------------------|
| GET     | `/api/alerts`                     | reader       | Liste paginée (filtres severity/status) |
| GET     | `/api/alerts/{id}`                | reader       | Détail d'une alerte, audit alert_view  |
| POST    | `/api/alerts/{id}/acknowledge`    | analyst      | Prise en compte, audit alert_acknowledge |
| POST    | `/api/alerts/{id}/resolve`        | analyst      | Résolution avec note, audit alert_resolve |
| POST    | `/api/alerts/{id}/assign`         | analyst      | Assignation à un utilisateur           |

### Règles (`/api/rules`)

| Méthode | Endpoint             | Rôle minimum  | Description                      |
|---------|----------------------|---------------|----------------------------------|
| GET     | `/api/rules`         | analyst       | Liste toutes les règles          |
| POST    | `/api/rules`         | administrator | Créer une règle, audit rule_create |
| PUT     | `/api/rules/{id}`    | administrator | Modifier une règle, audit rule_update |
| DELETE  | `/api/rules/{id}`    | administrator | Supprimer une règle, audit rule_delete |

### SOAR (`/api/soar`)

| Méthode | Endpoint                              | Rôle minimum | Description                          |
|---------|---------------------------------------|--------------|--------------------------------------|
| GET     | `/api/soar/playbooks`                 | analyst      | Liste des playbooks disponibles      |
| POST    | `/api/soar/playbooks/{id}/run`        | analyst      | Exécution manuelle d'un playbook     |

### Corrélation (`/api/correlation`)

| Méthode | Endpoint              | Rôle minimum  | Description                               |
|---------|-----------------------|---------------|-------------------------------------------|
| POST    | `/api/correlation/run` | administrator | Scan manuel sur fenêtre temporelle (défaut 30 min) |

## 3. Playbooks SOAR disponibles

### `block_ip`
- **Params** : `ip` (str), `reason` (str), `alert_id` (int|null)
- **Action** : POST vers `FIREWALL_API_URL/block`. Si absent : simulation avec log WARNING.
- **Résultat** : `{"status": "blocked"|"simulated", "ip": "..."}`

### `disable_account`
- **Params** : `username` (str), `reason` (str), `alert_id` (int|null)
- **Action** : Cherche l'utilisateur en SQL, passe `is_active = False`.
- **Résultat** : `{"status": "disabled"|"user_not_found", "username": "..."}`

### `escalate_admin`
- **Params** : `reason` (str), `alert_id` (int|null), `severity` (str)
- **Action** : Envoie un message d'escalade vers Slack, Teams et/ou email selon la config.
- **Résultat** : `{"status": "escalated", "channels_notified": [...]}`

## 4. Variables .env S2

```env
# Notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=siem@example.com
SMTP_PASSWORD=secret
ALERT_EMAIL_TO=soc-team@example.com

# SOAR
FIREWALL_API_URL=http://firewall-api.internal
```

Toutes les variables sont optionnelles. Les canaux non configurés sont ignorés silencieusement.

## 5. Scénarios d'attaque simulés — Comment tester

### Scénario 1 : Brute force SSH (RULE_001)
```bash
# Injecter 6 logs d'échec d'auth dans ES depuis la même IP
# Puis déclencher un scan manuel :
curl -X POST http://localhost:8000/api/correlation/run \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"window_minutes": 30}'
# Vérifier l'alerte créée :
curl http://localhost:8000/api/alerts -H "Authorization: Bearer <token>"
```

### Scénario 2 : Connexion hors horaires (RULE_002)
Injecter un log `log_type=auth` avec un `@timestamp` entre 0h et 6h ou après 22h UTC.

### Scénario 3 : Exfiltration / mouvement latéral (RULE_004)
Injecter des logs réseau avec `log_type=network` et `message` contenant "outbound" ou la même `source_ip` sur 4+ hosts distincts.

### Scénario 4 : Tester le playbook block_ip
```bash
curl -X POST http://localhost:8000/api/soar/playbooks/block_ip/run \
  -H "Authorization: Bearer <analyst_token>" \
  -H "Content-Type: application/json" \
  -d '{"params": {"ip": "1.2.3.4", "reason": "brute force test"}}'
```

### Scénario 5 : Exécuter les tests unitaires
```bash
cd backend
pytest tests/unit/s2/ -v
```

## 6. Ce qui est opérationnel (S2)

- Modèles SQL : `alerts`, `correlation_rules`, `playbook_executions`
- Moteur de corrélation : 5 règles actives, déduplication, audit
- Service d'alertes : CRUD complet + acknowledge/resolve/assign
- Notifier : webhook Slack/Teams + email SMTP async
- Playbooks SOAR : block_ip, disable_account, escalate_admin
- Routers : `/api/alerts`, `/api/rules`, `/api/soar`, `/api/correlation`
- Seed des 5 règles au démarrage
- 25+ tests unitaires sans Docker ni ES

## 7. Ce qui reste pour S3

- Scheduler automatique de corrélation (APScheduler, ex: toutes les 5 min)
- Dashboard temps réel (WebSocket ou SSE)
- Tableaux de bord MITRE ATT&CK
- Export PDF des rapports d'incidents
- Corrélation UEBA (comportement utilisateur)
- Intégration Threat Intelligence (MISP, OpenCTI)
- Multi-tenancy complète par subsidiary/environment
