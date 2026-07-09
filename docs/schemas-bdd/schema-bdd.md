# Schéma de base de données — Smart SIEM

Moteur : **Elasticsearch 8.13.0**
Module : **DATA** (périmètre indexation/stockage)

---

## Index `logs-siem` — Logs normalisés

Politique ILM : suppression automatique après `RETENTION_DAYS` jours (défaut : 30).

| Champ | Type ES | Justification |
|---|---|---|
| `timestamp` | `date` | Filtrage et tri temporel ; type natif pour les range queries |
| `source_ip` | `ip` | Type dédié pour le filtrage CIDR et les plages IP |
| `host` | `keyword` | Agrégations exactes par machine ; pas de tokenisation nécessaire |
| `log_type` | `keyword` | Valeurs d'énumération (auth/réseau/système/application) — filtrage exact |
| `severity` | `keyword` | Valeurs d'énumération (info/warning/critical) — filtrage exact |
| `raw_message` | `text` + `.keyword` | `text` pour la recherche full-text ; sous-champ `keyword` pour le tri exact |
| `tags` | `keyword` (array) | Étiquettes multiples — Elasticsearch gère les tableaux nativement |

---

## Index `siem-users` — Utilisateurs

| Champ | Type ES | Justification |
|---|---|---|
| `username` | `keyword` | Identifiant unique — correspondance exacte uniquement |
| `password_hash` | `keyword` | Hash stocké tel quel ; aucune analyse textuelle |
| `role` | `keyword` | Valeur d'énumération (admin/analyst/viewer…) |
| `created_at` | `date` | Filtrage temporel, audit |

---

## Index `siem-rules` — Règles de détection

| Champ | Type ES | Justification |
|---|---|---|
| `rule_id` | `keyword` | Identifiant métier unique — recherche exacte |
| `name` | `text` | Libellé lisible — recherche full-text utile |
| `type` | `keyword` | Catégorie de règle — filtrage exact |
| `active` | `boolean` | Activation/désactivation de la règle |
| `created_at` | `date` | Historique et audit |

---

## Index `siem-alerts` — Alertes

| Champ | Type ES | Justification |
|---|---|---|
| `alert_id` | `keyword` | Identifiant d'alerte unique |
| `severity` | `keyword` | Niveau de criticité — filtrage exact |
| `status` | `keyword` | État (open/closed/acknowledged) — filtrage exact |
| `related_logs` | `keyword` (array) | Références aux IDs de logs associés |
| `created_at` | `date` | Tri chronologique, TTL |

---

## Politique de rétention (ILM)

Nom de la politique : `logs-siem-policy`  
Phase `delete` : suppression des documents dont l'âge dépasse `RETENTION_DAYS` jours.  
Variable d'environnement : `RETENTION_DAYS` (défaut : `30`).

Seul l'index `logs-siem` est soumis à cette politique (les autres index ont un cycle de vie géré manuellement).

---

## Choix techniques clés

- **`keyword` vs `text`** : tous les champs servant au filtrage/agrégation (IP, host, severity…) sont en `keyword` pour éviter la tokenisation et permettre les agrégations exactes.
- **`ip` pour `source_ip`** : le type `ip` ES permet les filtres CIDR (`10.0.0.0/8`) et les plages IP, indispensables pour une analyse réseau.
- **`raw_message` multi-field** : `text` (analysé) pour `match` full-text + `keyword` (non analysé) pour `sort` et `term` exact.
- **Pas de `nested`** : les tags sont de simples `keyword` en tableau plat — suffisant pour les cas SIEM, pas de relation parent/enfant à préserver.
