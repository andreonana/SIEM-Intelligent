# Module UEBA — Documentation technique

## Vue d'ensemble

Le module UEBA (User and Entity Behavior Analytics) du Smart SIEM détecte les comportements anormaux
en comparant l'activité récente d'une entité à sa baseline historique. Il couvre les exigences du CDC V3 :
baseline comportementale, détection d'anomalies et scoring de risque.

---

## Architecture

```
Elasticsearch (logs bruts)
        │
        ├─► baseline.py       — calcule le profil historique de chaque entité (30 j)
        │
        ├─► behavior_analyzer.py — extrait le comportement récent (60 min par défaut)
        │
        ▼
anomaly_detector.py — compare baseline / récent → liste d'anomalies
        │
        ▼
risk_scorer.py — agrège les anomalies en un score 0-100
        │
        ▼
ueba_service.py — orchestre le pipeline et persiste en SQL (UEBAAnomaly, UEBARiskScore)
        │
        ▼
routers/ueba.py — expose les endpoints REST
```

---

## Entités analysées

| entity_type | Champ ES utilisé |
|---|---|
| `source_ip` | `source_ip` ou `src_ip` |
| `host` | `host` ou `hostname` |
| `user` | `user` ou `username` |

---

## Baseline comportementale

**Fichier :** `backend/app/modules/ueba/baseline.py`

La baseline est calculée dynamiquement depuis Elasticsearch sur une fenêtre configurable
(défaut `UEBA_BASELINE_DAYS = 30`).

Pour chaque entité, la baseline résume :

| Dimension | Description |
|---|---|
| `usual_hours` | Heures UTC couvrant 85 % de l'activité |
| `usual_source_ips` | Toutes les IPs sources observées |
| `usual_hosts` | Tous les hôtes observés |
| `dominant_log_types` | Types de logs couvrant 90 % de l'activité |
| `avg_daily_events` | Nombre moyen d'événements par jour |
| `avg_daily_auth_failures` | Moyenne journalière d'échecs auth |
| `sensitive_action_count` | Total d'actions sensibles sur la période |
| `is_reliable` | `false` si total_events < `UEBA_MIN_EVENTS_FOR_BASELINE` |

---

## Analyse comportementale récente

**Fichier :** `backend/app/modules/ueba/behavior_analyzer.py`

Extrait les mêmes dimensions que la baseline, mais sur la fenêtre récente
(défaut `UEBA_ANALYSIS_WINDOW_MINUTES = 60`).

---

## Détection d'anomalies

**Fichier :** `backend/app/modules/ueba/anomaly_detector.py`

### Tableau des anomalies et poids

| anomaly_type | Sévérité | Poids | Condition de déclenchement |
|---|---|---|---|
| `unusual_login_hour` | WARNING | +10 | Heure observée absente des `usual_hours` |
| `unseen_source_ip` | HIGH | +20 | IP source non vue dans `usual_source_ips` |
| `unseen_host` | HIGH | +15 | Hôte non vu dans `usual_hosts` |
| `abnormal_activity_volume` | HIGH/CRITICAL | +20 | Volume récent ≥ 3× la moyenne journalière |
| `auth_failure_spike` | HIGH/CRITICAL | +25 | Échecs auth ≥ 3× la moyenne, ou ≥ 5 si baseline = 0 |
| `abnormal_host_spread` | HIGH | +20 | > 3 hôtes distincts ET > 2× le nombre habituel |
| `anomalous_log_mix` | WARNING | +10 | Type de log non présent dans `dominant_log_types` |
| `sensitive_action_spike` | HIGH | +20 | Actions sensibles ≥ 3× la normale, ou ≥ 3 si baseline = 0 |

---

## Scoring de risque

**Fichier :** `backend/app/modules/ueba/risk_scorer.py`

Le score est la somme des poids des anomalies détectées, plafonné à 100.

| Plage de score | Niveau |
|---|---|
| 0 — 19 | `low` |
| 20 — 44 | `medium` |
| 45 — 69 | `high` |
| 70 — 100 | `critical` |

Les seuils sont configurables via `UEBA_RISK_MEDIUM_THRESHOLD`, `UEBA_RISK_HIGH_THRESHOLD`,
`UEBA_RISK_CRITICAL_THRESHOLD`.

La justification textuelle du score liste explicitement chaque anomalie et sa contribution.

---

## Variables de configuration (.env)

| Variable | Défaut | Description |
|---|---|---|
| `UEBA_BASELINE_DAYS` | `30` | Fenêtre de baseline en jours |
| `UEBA_ANALYSIS_WINDOW_MINUTES` | `60` | Fenêtre d'analyse récente en minutes |
| `UEBA_MIN_EVENTS_FOR_BASELINE` | `5` | Seuil de fiabilité de la baseline |
| `UEBA_RISK_MEDIUM_THRESHOLD` | `20` | Score → medium |
| `UEBA_RISK_HIGH_THRESHOLD` | `45` | Score → high |
| `UEBA_RISK_CRITICAL_THRESHOLD` | `70` | Score → critical |

---

## Endpoints API

| Méthode | Route | Rôle min | Description |
|---|---|---|---|
| GET | `/api/ueba/baseline` | reader | Baseline globale (filtrée par entity_type) |
| GET | `/api/ueba/baseline/{entity_type}/{entity_id}` | reader | Baseline d'une entité précise |
| POST | `/api/ueba/analyze` | analyst | Lance une analyse complète |
| GET | `/api/ueba/anomalies` | reader | Liste des anomalies persistées |
| GET | `/api/ueba/risk-scores` | reader | Scores de risque calculés |
| GET | `/api/ueba/entities/{entity_type}/{entity_id}/risk` | reader | Score de risque d'une entité |

### Exemple : lancer une analyse

```bash
curl -X POST http://localhost:8000/api/ueba/analyze \
  -H "Authorization: Bearer <JWT_ANALYST>" \
  -H "Content-Type: application/json" \
  -d '{"entity_type": "source_ip", "baseline_days": 30, "window_minutes": 60}'
```

### Exemple : lire les anomalies

```bash
curl http://localhost:8000/api/ueba/anomalies?entity_type=source_ip \
  -H "Authorization: Bearer <JWT_READER>"
```

### Exemple : score d'une IP

```bash
curl http://localhost:8000/api/ueba/entities/source_ip/10.0.0.1/risk \
  -H "Authorization: Bearer <JWT_READER>"
```

---

## Intégration avec alerting/corrélation

Le service UEBA crée automatiquement une alerte (`rule_id=UEBA_HIGH_RISK`) pour toute entité
dont le score atteint `high` ou `critical`. La déduplication journalière évite le flooding.
L'alerte est visible dans `/api/alerts` comme toute alerte de corrélation.

---

## Tests

```bash
cd backend
python3 -m pytest tests/unit/s2/test_ueba.py -v
# 34 tests — baseline, behavior, anomalies, scoring, service
```
