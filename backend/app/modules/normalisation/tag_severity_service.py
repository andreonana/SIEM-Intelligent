#   backend/app/modules/normalisation/tag_severity_service.py
#
#   Ce fichier contient relation entre chaque tag et sa sévérité. La severity d'un log est déterminée nia une table de correspondance severity -> [tags]
#    stocké dans Elasticsearch et modifiable dynamiquement par les analystes (proposition) et admins (validation).
#
#   *** STRUCTURE DE LA TABLE   ***
#   Un document par niveau de severity dans l'index, correspondant exactement à la règle métier (on part d'un niveau de severity pour savoir 
#    quels tags lui appartient) confirmée, au lieu de l'inverse.
#
#   *** REGLE NORMALE DE CALCUL DE severity D'UN LOG    ***
#   Parmi tous les tags d'un log, on cherche celui correspondant au niveau de severity le plus élevé dans la hiérarchie (critical > warning > info); et 
#    c'est ce niveau qui devient la severity du log entier. Si aucun tage du log n'a de correspondance dans la table, severity = "info" par défaut.

from datetime import datetime, timezone

from elasticsearch import AsyncElasticsearch

from app.core.config import settings

#   Hiérarchie du niveau de severity, du plus élevé au plus faible.
SEVERITY_HIERARCHY = ["critical", "warning", "info"]

#   Tags immunisées contre toute réévaluation automatiqeu de severity. La règle métier précise que ces tags précis ne puissent jamais être ajoutés ou 
#    modifiés dans la table tag -> severity par le workflow normal (validation ou lancement par admin):
#   -   "update log severity"   : Evite qu'un log d'audit de mise à jour de cette même table ne déclenche lui-même une nouvelle réévaluation en boucle.
#   -   "log hidden"            : Les logs de cycle de vie du SIEM sont générés automatiquement et leur severity ne doit jamais pouvoir être modifiée, même
#                                  par un admin. C'est la garantie d'intégrité du système de journalisation lui-même.
IMMUNE_AUDIT_TAG = "update log severity"
SERVICE_LIFECYCLE_TAG = "log hidden"
IMMUNE_TAGS = {IMMUNE_AUDIT_TAG, SERVICE_LIFECYCLE_TAG}

async def get_tag_severity_table(es_client: AsyncElasticsearch) -> dict[str, list[str]]:
    """
        Récupère la table complète de tag -> severity depuis Elasticsearch, sous la forme {"critical": [...], "warning": [...], "info": [...]}.
        Si l'index n'existe pas encore ou est vide (premier démarrage du système avant toutes configuration), retourne une table vide pour chaque niveau au 
         lieu de lever une exception.
    """
    table: dict[str, list[str]] = {level: [] for level in SEVERITY_HIERARCHY}

    try:
        response = await es_client.search(
            index=settings.es_tag_severity_index_name,
            query={"match_all": {}},
            size=len(SEVERITY_HIERARCHY),
        )
    except Exception:
        #   Index inexistant ou cluster indisponible; retourne la table vide construite, qui fera tomber tout log sur "info" par défaut au lieu de faire planter
        #    toute ingestion à cause d'une table de configuration absente.
        return table

    for hit in response["hits"]["hits"]:
        doc = hit["_source"]
        level = doc.get("severity")
        if level in table:
            table[level] = doc.get("tags", [])

    return table

def determine_severity_from_tags(tags: list[str], table: dict[str, list[str]]) -> str:
    """
        Détermine la severity d'un log  depuis ses tags et la table de correspondance déjà chargée.
        Parcourt la hiérarchie du plus élevé au plus faible (SEVERITY_HIERARCHY) et retourne le preminer
         niveau pour lequel au moins un tag du log correspond; ce qui revient excatement au tag avec le 
         plus haut niveau de severity parmi tous les tags du log.
        Retourne "info" si aucun tag du log n'a de correspondance dans la table. 
    """
    tags_set = set(tags)
    for level in SEVERITY_HIERARCHY:
        if tags_set.intersection(table.get(level, [])):
            return level
    return "info"

async def request_tag_severity_update(
    es_client: AsyncElasticsearch,
    requested_by: dict,
    severity: str,
    action: str,
    tag: str,
) -> dict:
    """
        Crée une demande de modification de la table tag -> severity.
        Paramètres:
            requested_by: informations de l'utilisateur demandeur (dict retourné par get_current_user, contient
             au moins "username" et "role").
            severity: le niveau de severity concerné.
            action: "add" pour ajouter le tag à ce niveau, "remove" pour le retirer.
            tag: le tag concerné par la demande.
        Si le demandeur a le rôle "administrator", la demande est auto-validée et appliquée immédiatement, tandis
         que si la demande vient de l'analyste, il faut d'abord la validation de l'admin pour qu'il prenne effet.
        Lève une ValueError su severity n'est pas une valeur reconnue, si action n'est ni "add", ni "remove", ou si
         le tag en question est immunisé.
    """
    if severity not in SEVERITY_HIERARCHY:
        raise ValueError(f"Niveau de severity inconnu: `{severity}`. Valeurs acceptées: {SEVERITY_HIERARCHY}.")

    if action not in {"add", "remove"}:
        raise ValueError(f"Action inconnue: `{action}`. Valeurs acceptées: add, remove.")

    if tag in IMMUNE_TAGS:
        raise ValueError(f"Le tag `{tag}` est immunisé contre toute modification. Il est réservé à la traçabiliré interne automatique du système.")

    is_permis = requested_by["role"] == "analyst"
    now = datetime.now(timezone.utc)

    document = {
        "requested_by": requested_by["username"],
        "requested_at": now.isoformat(),
        "severity": severity,
        "action": action,
        "tag": tag,
        "status": "validée" if is_permis else "en attente",
        "reviewed_by": requested_by["username"] if is_permis else None,
        "reviewed_at": now.isoformat() if is_permis else None,
    }

    response = await es_client.index(
        index=settings.es_tag_severity_update_index_name,
        document=document,
    )
    document["id"] = response["_id"]

    if is_admin:
        #   Auto-validation immédiate
        await _apply_tag_severity_change(es_client, severity, action, tag)
        await _write_audit_log(
            es_client,
            requested_by_username=requested_by["username"],
            requested_at=now,
            reviewed_by_username=requested_by["username"],
            reviewed_at=now,
            severity=severity,
            action=action,
            tag=tag,
        )

    return document

async def review_tag_severity_update(
    es_client: AsyncElasticsearch,
    update_id: str,
    reviewed_by: dict,
    approve: bool,
) -> dict | None:
    """
        Valide ou rejette une demande de modification en attente.
        Réservé aux administrateurs pour vérifier les demandes de mise à jour
        Retourne le document de demande mis à jour, ou None si l'identifiant ne correspond à aucune demande existante.
            Si approve=True, applique le changement à la table tag -> severity et écrit le log d'audit correspondant. 
            Si approve=False, marque simplement la demande comme rejetée, sans aucun effet sur la table
    """
    try:
        existing = await es_client.get(index=settings.es_tag_severity_update_index_name, id=update_id)
    except Exception:
        return None

    doc = existing["_source"]
    now = datetime.now(timezone.utc)
    new_status = "validée" if approve else "rejetée"

    await es_client.update(
        index=settings.es_tag_severity_update_index_name,
        id=update_id,
        doc={
            "status": new_status,
            "reviewed_by": reviewed_by["username"],
            "reviewed_at": now.isoformat(),
        },
    )

    if approve:
        await _apply_tag_severity_change(es_client, doc["severity"], doc["action"], doc["tag"])
        await _write_audit_log(
            es_client,
            requested_by_username=doc["requested_by"],
            requested_at=datetime.fromisoformat(doc["requested_at"]),
            reviewed_by_username=reviewed_by["username"],
            reviewed_at=now,
            severity=doc["severity"],
            action=doc["action"],
            tag=doc["tag"],
        )
    
    doc.update({"id": update_id, "status": new_status})
    return doc

async def _apply_tag_severity_change(es_client:AsyncElasticsearch, severity: str, action: str, tag: str) -> None:
    """
        Applique réellement un changement validé à la table tag -> severity dans Elasticsearch.
        Fonction privée, appelée uniquement depuis request_tag_severity_update() (auto-validation) et
         review_tag_severity_update() (validation explicite); jamais directement depuis le routeur HTTP,
         pour garantir qu'un changement n'est jamains appliqué sans passer par l'un de ces 2 chaînes de validation.
    """
    #   Utilise le niveau de severity lui-même comme identifiant du documetn au lieu de laisser Elasticsearch généré un identifiant.
    #   Ainsi, il existe toujours au plus un seul document de niveau de severity, ce qui simplifie la lecture et évite tout risque de
    #    de doublons ou incohérence entre plusieurs documents concurrents pour le même niveau.
    try:
        existing = await es_client.get(index=settings.es_tag_severity_index_name, id=severity)
        current_tags = set(existing["_source"].get("tags", []))
    except Exception:
        current_tags = set()

    if action == "add":
        current_tags.add(tag)
    else:
        current_tags.discard(tag)

    await es_client.index(
        index=settings.es_tag_severity_index_name,
        id=severity,
        document={"severity": severity, "tags": sorted(current_tags)},
    )

async def _write_audit_log(
    es_client: AsyncElasticsearch,
    requested_by_username: str,
    requested_at: datetime,
    reviewed_by_username: str,
    reviewed_at: datetime,
    severity: str,
    action: str,
    tag: str,
) -> None:
    """
        Ecrit le log d'audit de mise à jour de la table tag -> severity, exactement selon le format confimé.
        Ce document est indexé dans l'index des LOGS lui-même et non dnas un index séparé car il décrit ainsi explicitement au même
         titre que n'importe quel autre log système, une mise à jour.
    """
    action_label = "ajouté à" if action == "add" else "retiré de"

    raw_message = (f"Mise à jour de la table tag->severity. Demande effecturé le {requested_at.isoformat()} par '{requested_by_username}'. Validée le {reviewed_at.isoformat()} par '{reviewed_by_username}'. Le tag '{tag}' a été {action_label} au niveau de severité '{severity}'.")
    document = {
        "timestamp": reviewed_at.isoformat(),
        "source_ip": requested_by_username,
        "host": reviewed_by_username,
        "log_type": "système",
        "severity": "critical",
        "raw_message": raw_message,
        "tags": [IMMUNE_AUDIT_TAG],
        "received_at": reviewed_at.isoformat(),
    }

    await es_client.index(index=settings.es_logs_index_name, document=document)