# Rapport Sécurité S2 — Smart SIEM

**Date :** 2026-06-30  
**Auteur :** Équipe projet  
**Périmètre :** Sprint S2 — Corrélation, SOAR, Alerting, RBAC durci, Audit trail complet

---

## 1. Posture sécurité S2 vs S1

| Domaine | S1 | S2 |
|---------|----|----|
| Authentification | JWT basique, login/logout | JWT + audit trail complet (login, logout, create_user, role_update) |
| Autorisation | RBAC hiérarchique (reader/analyst/admin) | RBAC durci : 401 si token absent, 403 si rôle insuffisant, mode liste explicite |
| Corrélation | Absente | 5 règles MITRE (RULE_001–005), moteur temps-réel |
| SOAR | Absent | 3 playbooks opérationnels : block_ip, disable_account, escalate_admin |
| Notifications | Absentes | Slack, Teams, SMTP (configurables via .env) |
| Rétention | Absente | Purge automatique ES (APScheduler 02h UTC, loguée en SQL) |
| Config sécurité | Partielle | password_min_length, max_login_attempts, session_timeout_minutes ajoutés |
| Tests sécurité | Tests S1 basiques | Suite complète : scénarios d'attaque, SOAR, audit trail, notifications |

---

## 2. Scénarios d'attaque retenus

### Scénario 1 — Reconnaissance (T1595, T1046)

**Objectif :** Détecter une phase de découverte externe — scans de ports et accès à URLs sensibles.

**Logs attendus :**
- 12 logs `firewall` : `kernel: DROP IN=eth0 ... blocked port scan` depuis IP attaquante
- 10 logs `auth` : `failed authentication attempt to /admin|/.env|/phpinfo...`

**Règle déclenchée :** RULE_001 (10 auth failure depuis même IP → threshold=5 dépassé)

**Réponse SOAR :** Playbook `block_ip` — blocage de l'IP via firewall API ou simulation

**Commande de simulation :**
```bash
python3 scripts/security/simulate_attack.py --scenario 1 --url http://localhost:8000
```

---

### Scénario 2 — Mouvement latéral (T1021, T1110)

**Objectif :** Détecter un attaquant se déplaçant de machine en machine via SSH brute-force.

**Logs attendus :**
- 24 logs `auth` : `Failed password for root from 10.10.0.99 port XXXX ssh2`
- Même IP source (`10.10.0.99`) ciblant 4 hôtes : `web-01`, `web-02`, `db-master`, `auth-srv`
- 6 tentatives par hôte

**Règles déclenchées :**
- RULE_001 : 6 auth failures par hôte → threshold=5 dépassé → 4 alertes HIGH
- RULE_004 : même IP sur 4 hôtes distincts → 1 alerte CRITICAL

**Réponse SOAR :** `block_ip` + notification admin

**Commande de simulation :**
```bash
python3 scripts/security/simulate_attack.py --scenario 2 --url http://localhost:8000
```

---

### Scénario 3 — Exfiltration (T1041)

**Objectif :** Détecter un transfert massif de données vers l'extérieur.

**Logs attendus :**
- 5 logs `network` : `outbound data transfer detected: wget http://185.220.101.x/exfil.sh`
- 5 logs `firewall` : `outbound large transfer XXXMo to 45.33.32.x:443 data_exfil suspected`
- 6 logs `network` : `exfil pattern matched on flow ...`
- Total : 16 logs depuis IP `192.168.1.77`

**Règle déclenchée :** RULE_004 — keywords `outbound`, `exfil`, `data transfer` dans logs network/firewall → alertes CRITICAL

**Réponse SOAR :** `block_ip` de l'IP source + escalade admin

**Commande de simulation :**
```bash
python3 scripts/security/simulate_attack.py --scenario 3 --url http://localhost:8000
```

---

## 3. Règles de détection S2

| ID | Nom | Tactique MITRE | Technique | Criticité | Playbook |
|----|-----|---------------|-----------|-----------|---------|
| RULE_001 | Brute Force SSH/Auth | Credential Access | T1110 | HIGH | block_ip |
| RULE_002 | Connexion hors horaires | Initial Access | T1078 | WARNING | — |
| RULE_003 | Élévation de privilèges | Privilege Escalation | T1548 | HIGH | escalate_admin |
| RULE_004 | Exfiltration / IP suspecte multi-host | Exfiltration | T1041 | CRITICAL | block_ip |
| RULE_005 | Arrêt service de logs | Defense Evasion | T1562 | CRITICAL | escalate_admin |

**Paramètres RULE_001 :** threshold=5 auth failures depuis la même IP en 10 minutes  
**Paramètres RULE_004 mode multi-host :** même IP sur > 3 hôtes distincts dans la fenêtre temporelle

---

## 4. Playbooks SOAR fonctionnels

### block_ip
- **Description :** Bloque une adresse IP via l'API firewall externe ou simule le blocage si `FIREWALL_API_URL` n'est pas configuré.
- **Paramètres :** `ip` (str), `reason` (str), `alert_id` (int)
- **Audit :** Persisté dans `playbook_executions` SQL + `log_action("playbook_run")`
- **Exemple curl :**
```bash
curl -X POST http://localhost:8000/api/soar/playbooks/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"playbook_id": "block_ip", "params": {"ip": "10.10.0.99", "reason": "brute force", "alert_id": 42}}'
```

### disable_account
- **Description :** Désactive un compte utilisateur du SIEM (soft delete, `is_active=False`).
- **Paramètres :** `username` (str), `reason` (str), `alert_id` (int)
- **Audit :** `log_action("playbook_run")` + `log_action("disable_user")`
- **Exemple curl :**
```bash
curl -X POST http://localhost:8000/api/soar/playbooks/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"playbook_id": "disable_account", "params": {"username": "analyst", "reason": "compromis", "alert_id": 7}}'
```

### escalate_admin
- **Description :** Envoie une alerte urgente aux administrateurs via Slack, Teams ou email.
- **Paramètres :** `reason` (str), `alert_id` (int), `severity` (str)
- **Comportement :** Si aucun canal n'est configuré, retourne `channels_notified=[]` sans erreur.
- **Exemple curl :**
```bash
curl -X POST http://localhost:8000/api/soar/playbooks/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"playbook_id": "escalate_admin", "params": {"reason": "Exfiltration en cours", "alert_id": 3, "severity": "CRITICAL"}}'
```

---

## 5. Journalisation sécurité

| Événement | Action auditée | Route / code |
|-----------|---------------|-------------|
| Connexion réussie | `login` (result=success) | `POST /api/auth/login` → `auth.py:login()` |
| Connexion échouée | `login` (result=failure) | `POST /api/auth/login` → `auth.py:login()` |
| Déconnexion | `logout` | `POST /api/auth/logout` → `auth.py:logout()` |
| Création utilisateur | `create_user` | `POST /api/users` → `users.py:create_user()` |
| Modification de rôle | `role_update` | `PUT /api/users/{id}` → `users.py:update_user()` |
| Désactivation compte | `disable_user` | `DELETE /api/users/{id}` ou playbook |
| Exécution corrélation | `correlation_run` | `engine.py:run_correlation()` |
| Purge de rétention | `retention_cleanup` | `retention.py:run_retention_cleanup()` |
| Exécution playbook | `playbook_run` | `playbooks.py:_run_*()` |
| Envoi notification | `notification_send` | `notifier.py:notify_alert()` |

Toutes les entrées sont persistées dans la table SQL `audit_logs` (champs : timestamp, username, action, target, detail, ip_address, result).

---

## 6. Notifications

**Canaux disponibles :** Slack, Microsoft Teams, Email (SMTP)

**Configuration dans `.env` :**
```ini
# Slack : URL Incoming Webhook depuis api.slack.com/apps
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...

# Teams : URL du connecteur Incoming Webhook
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...

# Email SMTP
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=siem@example.com
SMTP_PASSWORD=secret
ALERT_EMAIL_TO=soc@example.com
```

**Comportement si canal absent :** Si une variable est vide ou absente, le canal est silencieusement ignoré. Aucune exception n'est levée. La liste `channels_notified` retournée est vide pour ce canal.

**Timeout HTTP :** 10 secondes (httpx.AsyncClient)

---

## 7. TLS et chiffrement

**État actuel :** Nginx configuré pour TLS dans `infra/nginx/nginx.conf` avec :
- Protocoles : TLSv1.2, TLSv1.3
- Ciphers : HIGH:!aNULL:!MD5
- Headers sécurité : `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security`
- Certificats auto-signés générés par `infra/tls/generate-certs.sh`

**Activation :**
```bash
bash infra/tls/generate-certs.sh
# Puis décommenter le bloc server HTTPS dans nginx.conf et le service nginx dans docker-compose.yml
docker compose up -d nginx
```

**Limitation :** Les certificats sont auto-signés (non reconnus par les navigateurs sans import CA). Pour la production, remplacer par des certificats Let's Encrypt ou d'une PKI interne.

---

## 8. Limitations S2

| Point | État S2 | Prévu pour S3 |
|-------|---------|---------------|
| Blocage IP | Simulé (FIREWALL_API_URL=vide) | Intégration firewall réelle |
| Max login attempts | Documenté, non appliqué | Verrouillage compte après N échecs |
| Révocation JWT | Non implémentée | Blacklist Redis ou rotation clé |
| MFA | Module présent (`mfa.py`), non branché aux endpoints | Intégration TOTP endpoint login |
| Exfiltration DLP | Détection par keyword seulement | Analyse volumétrique + ML (UEBA) |
| TLS Elasticsearch | Désactivé par défaut (`verify_certs=False`) | Activer avec CA cert en production |
| Playbook isolation réseau | Simulation uniquement | Intégration SDN/firewall |

---

## 9. Mode opératoire de test

### Pré-requis
```bash
cd /home/ems/Documents/projet\ Integrateur/backend
pip install pytest pytest-asyncio httpx
```

### Lancer tous les tests S2
```bash
python3 -m pytest tests/ -q --tb=short
```

### Lancer uniquement les tests de sécurité
```bash
python3 -m pytest tests/security/ -v
```

### Simuler les 3 scénarios d'attaque (backend démarré)
```bash
# Démarrer le backend
uvicorn app.main:app --reload &

# Simuler toutes les attaques
python3 ../scripts/security/simulate_attack.py --scenario all --url http://localhost:8000

# Vérifier les alertes générées
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin1234!"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s http://localhost:8000/api/v1/alerts \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### Tester le RBAC (token absent → 401)
```bash
curl -v http://localhost:8000/api/v1/alerts
# Attendu : HTTP 401
```

### Tester le RBAC (rôle insuffisant → 403)
```bash
TOKEN_READER=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"reader","password":"Reader1234!"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -v -X POST http://localhost:8000/api/users \
  -H "Authorization: Bearer $TOKEN_READER" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"Test1234!","role":"reader"}'
# Attendu : HTTP 403
```
