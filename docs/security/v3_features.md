# Smart SIEM V3 — Documentation des fonctionnalités

## 1. SOAR Auto-déclenché (modes AUTO / CONFIRM / MANUAL)

### Architecture
Le dispatcher SOAR (`app/modules/soar/dispatcher.py`) est appelé par le moteur de corrélation
après chaque création d'alerte, si la règle déclencheuse a un `soar_action` défini.

### Modes

| Mode    | Comportement |
|---------|-------------|
| AUTO    | Exécution immédiate du playbook dès la création de l'alerte. |
| CONFIRM | Création d'un enregistrement `PlaybookExecution(status="scheduled")` + exécution après `confirm_delay_seconds` (défaut : 60s) via APScheduler. Annulable via `DELETE /api/soar/scheduled/{id}`. |
| MANUAL  | Aucun déclenchement automatique. L'analyste déclenche manuellement via `POST /api/soar/playbooks/{id}/run`. |

### Endpoints SOAR
- `GET  /api/soar/playbooks` — liste des playbooks disponibles
- `POST /api/soar/playbooks/{id}/run` — déclenchement manuel
- `GET  /api/soar/scheduled` — exécutions CONFIRM (scheduled/success/cancelled)
- `DELETE /api/soar/scheduled/{execution_id}` — annulation d'une exécution planifiée

### Séquence AUTO
```
Corrélation → Alert créée → dispatch_soar(mode=AUTO)
  → run_playbook() immédiat
  → alert.soar_status = "executed"
  → audit log: soar_auto_executed
```

### Séquence CONFIRM
```
Corrélation → Alert créée → dispatch_soar(mode=CONFIRM)
  → PlaybookExecution(status="scheduled", scheduled_at=now+60s)
  → alert.soar_status = "scheduled"
  → audit log: soar_confirm_scheduled
  → APScheduler @ now+60s → _finalize_confirm_execution()
  → PlaybookExecution(status="success")
  → alert.soar_status = "executed"
```

---

## 2. Confidence Score par règle

Champ `confidence_score` (float, 0-100) sur `CorrelationRule` et propagé vers `Alert`.

### Valeurs par défaut des règles
| Règle      | Confidence | Mode SOAR |
|------------|-----------|-----------|
| RULE_001   | 90.0      | AUTO      |
| RULE_002   | 70.0      | MANUAL    |
| RULE_003   | 85.0      | CONFIRM   |
| RULE_004   | 95.0      | AUTO      |
| RULE_005   | 92.0      | AUTO      |

### Usage
- Stocké sur l'alerte pour priorisation
- Exposé dans tous les retours JSON (`/api/alerts`, `/api/rules`)
- Inclus dans les notifications email (`Confidence: 90.0%`)

---

## 3. Déduplication 5 minutes

### Clé de déduplication
Format : `{rule_id}:{source_ip}:{date}:slot{n}` où `slot = (heure*60 + minutes) // 5`

Chaque tranche de 5 minutes génère un slot différent, garantissant qu'une même alerte
ne peut pas être créée plus d'une fois par tranche de 5 min / IP / règle.

### Configuration
```python
DEDUPE_WINDOW_MINUTES = 5  # dans alert_service.py
```

---

## 4. Chaîne de custody SHA-256

### Principe
Chaque batch de logs ingérés génère un enregistrement `LogBatch` avec :
- `batch_id` : UUID unique
- `sha256` : hash SHA-256 du contenu `{batch_id, parent_sha256, logs}`
- `parent_sha256` : hash du batch précédent (chaîne)
- `log_count`, `source`, `created_at`

Le premier batch utilise `parent_sha256 = "0" * 64` (genesis hash).

### Intégration
Appeler `await record_batch(db, logs, source="ingestion_api")` à chaque ingestion.

### Endpoints
- `GET  /api/integrity/batches` — liste des batches (analyst+)
- `GET  /api/integrity/batches/{batch_id}` — détail d'un batch
- `POST /api/integrity/verify/{batch_id}` — vérification : recalcule le SHA-256 et compare

### Vérification
```json
POST /api/integrity/verify/{batch_id}
{"logs": [...logs originaux...]}
→ {"valid": true, "hash_valid": true, "chain_valid": true, ...}
```

---

## 5. Rate Limiting

### Middleware
`RateLimiterMiddleware` (Starlette BaseHTTPMiddleware) — sliding window en mémoire.

### Configuration (.env)
```
RATE_LIMIT_MAX_REQUESTS=100   # requêtes max par fenêtre
RATE_LIMIT_WINDOW_SECONDS=60  # durée de la fenêtre
```

### Limites par type
| Bucket    | Limite | Chemins concernés |
|-----------|--------|------------------|
| ingest    | max_requests | /api/ingest/*, /api/logs/* |
| auth      | max_requests // 10 (min 5) | /api/auth/login |
| api       | max_requests | tous les autres |

Retourne HTTP 429 avec header `Retry-After`.

---

## 6. Configuration SMTP réelle

Variables requises dans `.env` :
```
SMTP_HOST=smtp.gmail.com          # ou mail.infomaniak.com, smtp.office365.com
SMTP_PORT=587                     # 587 = STARTTLS, 465 = SSL
SMTP_USER=siem@example.com        # adresse expéditrice = login
SMTP_PASSWORD=app_password_here   # mot de passe ou App Password Gmail
ALERT_EMAIL_TO=admin@example.com  # destinataire des alertes
```

### Comportement
- Port 587 → STARTTLS automatique
- Port 465 → SSL/TLS direct
- Si SMTP_HOST manque → log WARNING, retourne False (pas de crash)
- Timeout : 15 secondes

### Tester l'envoi
```bash
curl -s -X POST http://localhost:8000/api/soar/playbooks/escalate_admin/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"params": {"reason": "test", "severity": "HIGH"}}'
```

---

## 7. Middlewares

### Ordre d'exécution (dernier ajouté = premier exécuté)
1. `RateLimiterMiddleware` — rejet 429 avant tout traitement
2. `AuthContextMiddleware` — décode JWT → `request.state.username`
3. `AuditLoggerMiddleware` — journalise les requêtes mutantes

### Audit HTTP
Actions journalisées : POST/PUT/PATCH/DELETE sur toutes routes + GET sur `/api/reports/`, `/api/audit`, `/api/users`, `/api/integrity/`.
Format dans `audit_logs` : `action=http_post`, `target=/api/alerts/1/ack`, `detail=status=200 duration_ms=45`.
