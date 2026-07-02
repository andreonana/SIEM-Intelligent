# Rapport d'audit sécurité final — Smart SIEM

**Date :** 2026-07-01
**Périmètre :** État réel du projet à l'issue des 3 semaines (S1-S2-S3)
**Nature du document :** Rapport factuel — n'affirme aucune conformité qui ne soit vérifiable dans le code.

---

## 1. Méthodologie

Ce rapport a été produit en auditant directement le code source exécuté (backend + frontend), en
testant les endpoints réels, et en vérifiant chaque affirmation par une commande exécutable. Aucune
donnée de ce rapport n'est déclarative sans preuve technique associée.

---

## 2. Authentification et contrôle d'accès

| Contrôle | État réel | Preuve |
|---|---|---|
| Authentification locale | ✅ Implémentée | `POST /api/auth/login`, hachage bcrypt (passlib) |
| MFA TOTP (RFC 6238) | ✅ Implémentée | `app/modules/rbac/mfa.py`, endpoints `/api/auth/mfa/*`, 21 tests unitaires |
| RBAC 3 niveaux | ✅ Implémenté | `require_role()` hiérarchique (reader < analyst < administrator) sur toutes les routes sensibles |
| Ségrégation par périmètre (équipe/service/filiale/environnement) | ⚠️ Partiel | Champs `team`/`service`/`subsidiary`/`environment` existent sur `User` mais **ne filtrent aucune donnée** — actuellement des métadonnées non exploitées pour le cloisonnement d'accès aux logs |
| Verrouillage après tentatives échouées | ❌ Non implémenté | `max_login_attempts` existe en config mais n'est appliqué nulle part dans `auth.py` |

**Écart à corriger en priorité** : le cloisonnement organisationnel (exigence CDC 3.7) n'est aujourd'hui qu'un
enregistrement de métadonnées, pas un contrôle d'accès effectif.

---

## 3. Chiffrement et protection des données

| Contrôle | État réel | Preuve |
|---|---|---|
| TLS communications | ✅ Nginx configuré avec certificats | `infra/tls/`, `docker-compose` expose 443 |
| Chiffrement au repos (BDD) | ❌ Non vérifié | Aucune configuration de chiffrement disque n'est présente dans les fichiers du projet (dépend de l'hébergeur en production) |
| Mots de passe hachés | ✅ | bcrypt via passlib, jamais stocké en clair |
| Secrets `.env` | ⚠️ Valeurs par défaut non sécurisées présentes | `JWT_SECRET`, `INGEST_API_KEY`, `ELASTICSEARCH_PASSWORD` ont des valeurs `[INSECURE-DEFAULT]` explicitement marquées — **à remplacer avant toute mise en production réelle** |

---

## 4. Intégrité et traçabilité

| Contrôle | État réel | Preuve |
|---|---|---|
| Chaîne de custody SHA-256 des logs | ✅ Implémentée et testée | `services/integrity_service.py`, endpoint `/api/integrity/verify/{batch_id}`, vérifié fonctionnel (hash valide/invalide détecté sur données altérées) |
| Journal d'audit des actions utilisateurs | ✅ Implémenté | Table `audit_logs`, actions journalisées : login/logout/create_user/role_update/alert_view/alert_acknowledge/investigation_flag |
| Immuabilité du journal d'audit (WORM) | ❌ Non implémentée | Aucun trigger base de données n'empêche l'UPDATE/DELETE sur `audit_logs`. Le frontend ne prétend plus le contraire (badge "WORM" retiré lors de l'audit de cette session) |
| Marquage d'investigation persistant | ✅ Implémenté (cette session) | Table `investigation_flags`, endpoint `POST /api/investigation/{entity_id}/flag` |

---

## 5. SOAR — automatisation de la réponse

| Playbook | État réel | Preuve |
|---|---|---|
| `block_ip` | ✅ Réel, intégration pare-feu opérationnelle | Appelle réellement le service `firewall-controller` (`infra/firewall-controller/`, FastAPI + `iptables` réel via subprocess). `status: "blocked"` uniquement si le firewall confirme réellement le blocage (le corps JSON est lu, plus de confiance aveugle au code HTTP) ; `status: "failure"` explicite si la config est absente ou si le blocage échoue — plus jamais de `simulated` |
| `disable_account` | ✅ Réel | Modifie réellement `User.is_active` en base |
| `escalate_admin` | ✅ Réel (partiellement) | Email SMTP réel si configuré ; Slack/Teams réels si `SLACK_WEBHOOK_URL`/`TEAMS_WEBHOOK_URL` renseignés — sinon canal absent sans erreur trompeuse |

**Portée du blocage `block_ip`** : le service `firewall-controller` applique la règle iptables
dans son propre network namespace (voir `docs/security/firewall-controller.md`), pas sur
l'hôte Docker ni sur les autres conteneurs — un choix assumé pour rester démontrable sans
accès privilégié à l'hôte. Ce n'est donc pas (encore) un pare-feu de périmètre protégeant
l'ensemble de l'infrastructure.

---

## 6. Moteur de corrélation — détection réelle

**Bug corrigé durant cet audit** : la fonction `_message()` du moteur de corrélation lisait le champ
Elasticsearch `message`, qui n'existe pas dans le mapping réel (le pipeline de normalisation stocke le
contenu sous `raw_message`). Ce bug empêchait silencieusement toute règle basée sur le contenu du
message de se déclencher (notamment **RULE_001 — brute-force**, qui ne créait jamais aucune alerte).

Vérification post-correction sur le dataset de test 30 jours (voir section 8) :

| Règle | Détection | Preuve |
|---|---|---|
| RULE_001 (brute-force) | ✅ Détectée | Alerte créée avec `source_ip=203.0.113.77`, 60 tentatives, correspond exactement à l'IP injectée |
| RULE_002 (hors horaires) | ✅ Détectée | 34 alertes sur les connexions nocturnes du scénario de mouvement latéral |
| RULE_003 (élévation de privilèges) | ✅ Détectée | 2 alertes |
| RULE_004 (exfiltration/IP suspecte) | ✅ Détectée | 5 alertes sur le pattern d'exfiltration lente |
| RULE_005 | ✅ Détectée | 3 alertes |

---

## 7. Résultats de tests d'intrusion simulés

Les tests d'intrusion n'ont pas été menés avec un outil dédié (Caldera, Metasploit) mais via l'injection
d'un dataset de logs simulant 3 scénarios d'attaque réels (voir section 8), analysés par le moteur de
corrélation réel du SIEM. Résultat : **les 3 scénarios sont détectés** après correction du bug `_message()`.

Aucun test d'intrusion réseau actif (scan de ports réel, tentative d'exploitation réelle) n'a été mené
contre l'infrastructure elle-même — seule la capacité de détection sur des logs représentatifs a été
vérifiée.

---

## 8. Dataset 30 jours + 3 attaques cachées (exigence CDC V3)

**État avant cette session** : les dossiers `dataset/scenarios/{brute-force,lateral-movement,exfiltration}/`
ne contenaient que des fichiers JSON de 0 octet (placeholders vides). Les scripts
`dataset/generators/log_generator.py` et `attack_simulator.py` étaient également vides. **Le dataset
exigé par le CDC n'existait pas réellement.**

**État après cette session** : `dataset/generators/log_generator.py` génère réellement 30 jours de trafic
syslog de base (~1200 logs) et y injecte :
1. Brute-force SSH (60 échecs + 1 succès depuis une IP externe)
2. Mouvement latéral (compte compromis sur 4 hôtes internes en séquence)
3. Exfiltration lente (volume croissant sur 5 jours, fractionné)

Le script a été exécuté et ingéré réellement dans Elasticsearch (1294 logs indexés, vérifié via
`GET /api/v1/logs`), et les 3 scénarios ont été confirmés détectables par le moteur de corrélation réel
(section 6).

---

## 9. Conformité RGPD / ISO 27001 — état honnête

**Aucun score de conformité chiffré n'est calculé par le backend.** Toute vue affichant un pourcentage
« conformité ISO/RGPD » a été retirée du frontend lors de l'audit anti-mock de cette session car les
formules précédentes étaient des heuristiques arbitraires sans méthodologie d'audit réelle.

| Article / Contrôle | État réel |
|---|---|
| Journalisation des accès (ISO 27001 A.12.4.1) | ✅ Implémentée (audit trail) |
| Protection des journaux (A.12.4.2) | ⚠️ Partielle — pas d'immuabilité DB (voir section 4) |
| Contrôle d'accès (A.9.1.1) | ✅ RBAC hiérarchique implémenté |
| Registre des traitements (RGPD Art. 30) | ❌ Non implémenté — aucun registre formel dans le projet |
| Droit à l'effacement / portabilité (RGPD) | ❌ Non implémenté |
| Politique de rétention configurable | ✅ Implémentée (`RETENTION_DAYS`, purge automatique planifiée) |

---

## 10. Synthèse des écarts restants (priorisés)

1. **Cloisonnement organisationnel non effectif** (section 2) — les champs existent mais ne filtrent rien.
2. **Blocage `block_ip` limité au network namespace du contrôleur** — pas encore un pare-feu de périmètre protégeant toute l'infrastructure (voir section 5).
3. **Pas d'immuabilité du journal d'audit** (pas de contrainte WORM en base).
4. **Aucun registre RGPD des traitements** ni mécanisme de droit à l'effacement.
5. **Verrouillage de compte après échecs répétés** non implémenté malgré la configuration existante.

Ce rapport ne recommande pas de considérer le projet comme "conforme RGPD/ISO 27001" en l'état :
il documente une base technique solide sur l'authentification, la traçabilité et la détection, avec des
écarts organisationnels et réglementaires clairement identifiés ci-dessus.
