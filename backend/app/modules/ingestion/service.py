#   backend/app/modules/ingestion/service.py
#
#   Ce fichier orchestre le traitement complet d'un log entrant
#       Il délègue toute la transformation (analyse syntaxique et classification) au module de 
#        normalisation via sa façade publique (normalize()), 
#        puis assume sa propre responsabilité spécifique: Stocker durablement les résultats dans Elasticsearch.
#
#   La seule dépendance de ce fichier vers le module de normalisation passe par l'import de normalize,
#    exclusivement via sa façade publique, jamais via les fichiers internes de ce module (analyseur syntaxique
#    ou fichier de classification). Si l'implémentation interne d ece module change, pas besoin de modification 
#    dans ce fichier.

import os
from datetime import datetime, timezone

from elasticsearch import AsyncElasticsearch

from app.modules.normalisation.service import normalize
from app.schemas.log import RawLogIngest

#   ********    DEPENDANCE EXTERNE  ********
#   Variable : Es_LOGS_INDEX_NAME
#   Attendue dans le fichier .env partagé à la racine du projet.
#   Donné par le concepteur des index Elasticsearch (data/sécurité) car c'est le nom exact de l'index Elasticsearch
#    dans lequel les logs normalisés doivent être stockés.
#   Ce nom doit correspondre précisement à un index déjà créé avec son mapping (définition des types de champs) sur 
#    le cluster Elasticsearch.
#   Si ce nom diffère du nom réellement configuré sur le cluster, l'indexation échouera ou créera un index incorrect par défaut.
#
#   Une valeur par défaut est fournie ("smart-siem-ligs") uniquement pour permettre de démarrer le développement local 
#    avant que cette variacle ne soit officiellement communiquée. Dès que la variable d'environnement réelle est définie 
#    dans .env, elle prend automatiquement le dessus sur cette valeur par défaut.
LOGS_INDEX_NAME = os.getenv("ES_LOGS_INDEX_NAME", "smart-siem-logs")

async def ingest_single_log(raw_log: RawLogIngest, es_client: AsyncElasticsearch) -> dict:
    """
    Traite un log brute de bout en bout et l'indexe dans Elasticsearch.
    Ce traitement correspond au flux de production réel du système:
        1 appel à cette fonction = 1seul log traité et socké.
        Aucun traitement par lots présent ici(ingest_bulk_logs pour l'outil de développement séparé).
    Paramètres:
        raw_log: log brut reçu, déjà validé par le schéma RawLogIngest
        es_client: Client Elasticsearch asynchrone partagé, injecté par FastAPI via la dépendance get_es_client()
    Retourne un dictionnaire représentant le log tel qu'il a été indexé, avec son identifiant généré par Elasticsearch.
    Lève une ValueError si la normalisation échoue (format de log invalide).
    Lève toute autre exception si la communication avec Elasticsearch échoue (cluster indosponible, mapping incompatible).
    """

    #   Step 1: Délégation de la transformation au module de normalisation.
    #   Elle encoit le log brut et reçoit le résultat final structuré sans connaître le scheminement.
    normalized = normalize(raw_message=raw_log.raw_message, source=raw_log.source)

    #   Step 2: Construction du document JSON à indexer. 
    #   Avec Elasticsearch, contrairement à la DB relationnelle, il n'existe pas de classe représentant une table.
    #    on construit directement un dictionnaire Python, qui sera sérialisé tel que en JSON et envoyé au cluster.
    #
    #   Le champ "timestamp" est explicitement converti en string au format ISO 8601 (via .isoformat()) car
    #    Elasticsearch attend ce format pour les champs de tyep "date" dans son mapping.
    document = {
        "timestamp": normalized.timestamp.isoformat(),
        "source_ip": normalized.source_ip,
        "host": normalized.host,
        "log_type": normalized.log_type,
        "severity": normalized.severity,
        "raw_message": normalized.raw_message,
        "tags": normalized.tags,
        "received_at": datetime.now(timezone.utc).isoformat(),
    }
    #   Important pour la cohérance:
    #       La structure de ce dictionnaire (ces 7 clés précises) doit correspondre exactement aux champs définis dans le 
    #        mapping de l'index Elasticsearch ES_LOGS_INDEX_NAME. Si la définition de cet index évolue (add/delete a champ),
    #        ce dictionnaire devra être mis à jour en conéquence.

    #   Step 3: Indexation du document dans Elasticsearch.
    #   client.index() rest l'opération qui envoie ce document au cluster et le rend immédiatement persistant et rechargable.
    #   On ne précise pas de paramètrce "id=" explicite car Elastisearch en génère automatiqeument 1 pour chaque document,
    #    cohérent avec le principe "1 appel = 1 log" décrit au par avant.
    response = await es_client.index(
        index=LOGS_INDEX_NAME,
        document=document,
    )

    #   Step 4: Cosntruction de la réponse retournée à l'appelant.
    #   La réponse d'Elasticsearch (response) contient des métadonnées techniques (l'identifiant généré, l'index utilisé ...).
    #   On reconstruit un dictionnaire propre, cohérent avec le schéma NormalizedLogOut attendu par l'API en injectant
    #    l'identifiant généré par Elasticsearch dans le champ "id".
    return {
        "id": response["id"],
        "timestamp": normalized.timestamp,
        "source_ip": normalized.source_ip,
        "host": normalized.host,
        "log_type": normalized.log_type,
        "severity": normalized.severity,
        "raw_message": normalized.raw_message,
        "tags": normalized.tags,
    }

async def ingest_bulk_logs(raw_logs: list[RawLogIngest], es_client: AsyncElasticsearch) -> tuple[list[dict], list[str]]:
    """
    Traite une liste longue en une seul opération.
    Cette fonction est un outil de développement et de test uniquement, servant à charger rapidement un grand nombre de logs simulés
     sans devoir effectuer 1 requête HTTP / logs.
    Elle n'est jamais utilisée pour le flux de production réel, qui reste strictement "1 appel HTTP = 1 log".
    Retourne un tuple contenant la liste des logs traités avec succès et la liste des messages d'erreur rencontrés, plutôt que de
     lever une exception au premier problème: 1 lot de plusieurs centaines de logs, il est important de savoir exactement lesquels
     ont échouées et pourquoi, sans perdre le traitement de tous les autres logs du même lot.
    """
    successful_entries: list[dict] = []
    error_messages: list[str] = []

    for index, raw_log in enumerate(raw_logs):
        try:
            #   Réutilisation directe de la fonction unitaire ci-dessus.
            #   Aucune duplication de logiques entre traitement en lot et celui unitaire.
            #   k$Le traitement en lot n'est qu'une boucle du chemin de traitement normal.
            entry = await ingest_single_log(raw_log, es_client)
            successful_entries.append(entry)
        except ValueError as exc:
            #   Erreur de normalisation:
            #   Le mesage brut de ce log précis n'a pas pu être analysé (format invalide).
            #   On continue le traitement des logs suivants du même lot.
            error_messages.append(f"Log #{index}: {exc}")
        except Exception as exc:
            #   Erreur de communication avec Elasticsearch lui-même (cluster indisponible, mapping rejeté par le serveur...).
            #   On le distingue clairement d'une erreur de données. Ici, le problème vient de l'infra de stockage et non du log.
            error_messages.append(f"Log #{index}: erreur Elasticsearch - {exc}")

        return successful_entries, error_messages