#   backend/app/api/v1/routers/logs.py
#
#   Ce ichier déinit les endpoints HTTP liés à l'ingestion de logs.
#   Sa seule responsabilité est de traduire une requête HTTP en appel
#    à la logique métier (module d'ingestion), puis de traduire le 
#    résultat ou les erreurs de cette logique en réponse HTTP appropriée.
#   Ce fichier ne contient jamais de logique métier lui-même.

from fastapi import APIRouter, Depends, HTTPException, status
from elasticsearch import AsyncElasticsearch

from app.db.elasticsearch_client import get_es_client
from app.schemas.log import RawLogIngest, NormalizedLogOut, BulkIngestResult
from app.modules.ingestion.service import ingest_bulk_logs, ingest_single_log

#   Protection locale et basique de cet endroit (clé API de secours et limitation de débit) 
#    pour le détail de ce que ces 2 fonctions font et ne font pas
from app.modules.rbac.local_protection import verify_simple_api_key, enforce_rate_limit

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

@router.post(
    "/ingest",
    response_model=NormalizedLogOut,
    status_code=status.HTTP_201_CREATED,
    #   *** RÔLE ATTENDU POUR CET ENDPOINT : "analyst" ou "admin"   ***
    #   Cet endpoint reçoit un nouveau log et l'indexe dans le système (écriture)
    #   Un rôle "reader" ne devrait pas pouvoir injecter de nouvelles données dans 
    #    le système.
    #
    #   En attendant la réception du rbac.py, la protection active sur cet
    #    endpoint est purement locale et basique (clé API + limitation de débit). 
    #   Dès que rbac.py fournie, remplacer la ligne ci-dessous par quelque chose comme:
    #   
    #   from rbac import require_role
    #   dependencies=[Depends(require_role("analyst"))]
    #
    #   Le nom exact ede la fonction et sa syntaxe d'appel devront être validés
    #    à la réception de rbac.py réel.
    dependencies=[
        Depends(verify_simple_api_key),
        Depends(enforce_rate_limit),
    ],
)

async def ingest_log(
    raw_log: RawLogIngest,
    es_client: AsyncElasticsearch = Depends(get_es_client),
):
    """
    Reçoit un log brut, le fait normaliser par le module de normalisation, puis l'indexe dans Elasticsearch via le module d'ingestion.

    C'est l'endpoint de production réel: 1 appel HTTP = 1 log traité.
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

    return log_entry

@router.post(
    "/ingest/bulk",
    response_model=BulkIngestResult,
    #   *** RÔLE ATTENDU POUR CET ENDPOINT : "administrateur"   ***
    #   Cet endpoint permet d'injecter un grand nombre de logs en une seule requête.
    #   Il sagit d'un outil de développement et de test (ex. pour charger données simulées), pas du flux de production réel.
    #   Un rôle plus restricti que pour l'ingestion unitaire est recommandé car un appel malveillant à cet endpoint aurait un impact 
    #    plus important (insertion massive de données).
    #
    #   Même remarque que pour l'endpoint précédent concernant le remplacement futur par Depends(require_role("admin")).
    dependencies=[
        Depends(verify_simple_api_key),
        Depends(enforce_rate_limit),
    ],
)

async def ingest_logs_bulk(raw_logs: list[RawLogIngest], es_client: AsyncElasticsearch = Depends(get_es_client),):
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