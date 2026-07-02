#   backend/app/api/v1/routers/logs.py
#
#   Ce ichier déinit les endpoints HTTP liés à l'ingestion de logs.
#   Sa seule responsabilité est de traduire une requête HTTP en appel
#    à la logique métier (module d'ingestion), puis de traduire le 
#    résultat ou les erreurs de cette logique en réponse HTTP appropriée.
#   Ce fichier ne contient jamais de logique métier lui-même.

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from elasticsearch import AsyncElasticsearch

from app.core.config import settings
from app.db.elasticsearch_client import get_es_client
from app.schemas.log import RawLogIngest, RawLogIngestJSON, NormalizedLogOut, BulkIngestResult
from app.modules.ingestion.service import ingest_bulk_logs, ingest_single_log, ingest_single_log_json
from app.modules.ingestion.read_service import list_logs, get_log_by_id

#   Protection locale et basique de cet endroit (clé API de secours et limitation de débit) 
#    pour le détail de ce que ces 2 fonctions font et ne font pas
from app.modules.rbac.local_protection import verify_simple_api_key, enforce_rate_limit
from app.modules.rbac.roles import require_role
from app.modules.rbac.field_visibility import filter_document_for_role, filter_documents_for_role

from app.modules.correlation.service import evaluate_for_source, should_trigger_immediate_scan

router = APIRouter(prefix="/api/v1/logs", tags=["logs"])

#   *** ENDPOINT LOGIN START    ***
#
#   Aucun endpoint de connexion (login) n'est défini dans ce fichier, ni
#    dans aucun autre fichier de ce projet à ce jour.
#
#   La gestion de la connexion, du hachage des mots de passe, et de la
#    création des tokens JWT est intégralement déléguée au fichier
#    auth.py fourni par l'équipe sécurité. Ce fichier exposera lui-même
#    son propre routeur d'authentification, à brancher dans
#    backend/app/main.py de la même façon que les routeurs de ce fichier.
#
#   Aucune action n'est requise ici tant que auth.py n'a pas été reçu.
#
#   *** ENDPOINT LOGIN END  ***

#   =================================================================================
#       PORTES D'ENTREE:    Réception de données depuis d'autres services
#   =================================================================================

@router.post(
    "/ingest",
    response_model=NormalizedLogOut,
    status_code=status.HTTP_201_CREATED,
    summary="Ingestion d'un log brut (Syslog / agent)",
    dependencies=[
        Depends(verify_simple_api_key),
        Depends(enforce_rate_limit),
    ],
)

async def ingest_log(
    raw_log: RawLogIngest,
    background_tasks: BackgroundTasks,
    es_client: AsyncElasticsearch = Depends(get_es_client),
):
    """
        Reçoit un log brut, le fait normaliser par le module de normalisation, puis l'indexe
        dans Elasticsearch via le module d'ingestion.
        C'est l'endpoint de production réel: 1 appel HTTP = 1 log traité.
        Rôle requis: clé API statique.
        Après ingestion, si le log remplit les critères déclenchant immédiat, un scan de corrélation ciblé est lancé en arrière-plan sans bloquer la réponse.
    """
    try:
        log_entry = await ingest_single_log(raw_log, es_client)
    except ValueError as exc:
        #   Erreur de normalisation: Message brut n'a pas pu être analysé correctement 
        #    (format Syslog ou JSON invalide, champ obligatoire manquant). 
        #   Le code HTTP 422 indique que la requête était syntaxiquement valide, 
        #    mais que son contenu métier pose problème.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        #   Erreur de communication avec Elasticsearch lui-même (cluster indisponible, 
        #    mapping rejeté par le serveur...).
        #   Le code HTTP 503 indique un problème d'inrastructure, distinct d'un problème donnée.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Erreur de communcation avec Elasticsearch: {exc}",
        ) from exc

    if should_trigger_immediate_scan(
        log_entry.get("log_type", ""),
        log_entry.get("severity", ""),
        log_entry.get("tags", [])
    ):
        background_tasks.add_task(
            evaluate_for_source,
            es_client,
            log_entry.get("source_ip"),
            log_entry.get("host"),
        )

    return log_entry

@router.post(
    "/ingest/json",
    response_model=NormalizedLogOut,
    status_code=status.HTTP_201_CREATED,
    summary="Ingestion d'un log JSON natif (FIleBeat)",
    dependencies=[
        Depends(verify_simple_api_key),
        Depends(enforce_rate_limit),
    ]
)

async def ingest_log_json(
    raw_log:            RawLogIngestJSON,
    background_tasks:   BackgroundTasks,
    es_client:          AsyncElasticsearch = Depends(get_es_client),
):
    """
        Reçoit un log déjà structuré comme objet JSON natif (et non string), le fait normaliser, puis l'indexe
        dans Elasticsearch.
        Endpoint dédié aux sources qui parlent déjà JSON nativement (comme agent Filebeat), pour éviter la friction
        de devoir sérialiser leur JSON en string juste pour que ce serveur le redésérialise immédiatement après réception.
    """
    try:
        log_entry = await ingest_single_log_json(raw_log.raw_json, es_client)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Erreur de communication avec Elasticsearch: {exc}",
        ) from exc

    if should_trigger_immediate_scan(log_entry.get("log_type", ""), log_entry.get("severity", ""), log_entry.get("tags", []),):
        background_tasks.add_task(
            evaluate_for_source,
            es_client,
            log_entry.get("source_ip"),
            log_entry.get("host"),
        )
    
    return log_entry

@router.post(
    "/ingest/bulk",
    response_model=BulkIngestResult,
    summary="Ingestion en lot (tests et développement uniquement)",
    dependencies=[
        Depends(verify_simple_api_key),
        Depends(enforce_rate_limit),
    ],
)

async def ingest_logs_bulk(
        raw_logs: list[RawLogIngest], 
        es_client: AsyncElasticsearch = Depends(get_es_client),
    ):
    """
    Reçoit une liste de logs bruts et les traite tous via le module d'ingestion.
    Cet endpoint est un outil de développement et de test uniquement:
        Il sert à charger rapidement un grand nombre de logs simulés (ex. générés par un script Faker, pour peupler 
         Elasticsearch avec des données de test).
        Il n'est jamais utilisé dans le flux de production réel.
    """
    successful, errors = await ingest_bulk_logs(raw_logs, es_client)

    return BulkIngestResult(
        total_received=len(raw_logs),
        total_inserted=len(successful),
        total_failed=len(errors),
        errors=errors,
    )

#   =================================================================================
#       PORTES DE SORTIE:   Envoie de données vers d'autres services
#   =================================================================================

@router.get(
    "",
    summary="Liste des logs (paginée)"
    #   *** RÔLE ATTENDU POUR CET ENDPOINT : "reader"   ***
    #   Cet endpoint permet de recevoir partiellement les logs pour de simple consultations.
)

async def get_all_logs(
    page: int = 1,
    page_size: int = 50,
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user: dict = Depends(require_role("reader")),
):
    """
        Retourne la liste des logs stockés, avec pagination, du plus récent au plus ancien.
        Paramètres de requête optionnels:
            page: numéro de page (défaut: 1).
            page_size: nombre de logs par page (défaut: 50)
    """
    try:
        result =  await list_logs(es_client, page=page, page_size=page_size)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Erreur de communication avec Elasticsearch: {exc}",
        ) from exc

    result["logs"] = filter_documents_for_role(result.get("logs", []), user["role"])
    return result

@router.get(
    "/{log_id}",
    summary="Détail d'un log"
    #   *** RÔLE ATTENDU POUR CET ENDPOINT : "reader"   ***
    #   Cet endpoint permet de consulter simplement les logs (partiellement)
)

async def get_log(
    log_id: str,
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user: dict = Depends(require_role("reader")),
):
    """
    Retourne un log précis à partir de son identiiant Elasticsearch.
    Retourne une erreur 404 si aucun log ne correspond à cet identifiant.
    """
    log = await get_log_by_id(es_client, log_id)
    if log is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Aucun log trouvé dans l'identifiant '{log_id}'.",
        )
    return filter_document_for_role(log, user["role"])