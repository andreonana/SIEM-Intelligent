#   backend/app/modules/ingestion/read_service.py
#
#   Ce fichier complète modules/ingestion/service.py qui n egère que l'écriture des logs dans Elasticsearch 
#    avec les opérations de lecture (lister les logs, récupérer un log précis par son identifiant).
#
#   Ce fichier est volontairement séparé de service.py (écriture (ingestion) et lecture (consultation) sont 
#    deux responsabilités différentes) qui n'ont pas besoin d'être mélangées dans le même fichier, même si 
#    elles opèrent sur le même index Elasticsearch.

from elasticsearch import AsyncElasticsearch

from app.core.config import settings

async def list_logs(es_client: AsyncElasticsearch, page: int = 1, page_size: int = 50) -> dict:
    """
    Liste les logs stockés dans Elasticsearch, avec pagination.
    Paramètres:
        es_client:  Le client Elasticsearch asynchrone partagé.
        page: numéro de page demandé, à partir de 1.
        page_size: nombre de logs à retourner par page.
    Retourne un dictionnaire contenant le nombre total de logs correspondants et la liste des logs de la page
     demandée, triés du plus récent au plus ancien.
    """
    #   Calcul du décalage (offset) à partir du numéro de page: La page 1 commence au document 0, celle 2 à page_size, et.
    from_offset = (page - 1)*page_size

    response = await es_client.search(
        index=settings.es_logs_index_name,
        from_=from_offset,
        size=page_size,
        sort=[{"timestamp": {"order": "desc"}}],                #   Sortie décroissante (du plus récent au moins récent)
        query={"match_all": {}},
    )

    hits = response["hits"]["hits"]
    total = response["hits"]["total"]["value"]

    logs = [
        {"id": hit["_id"], **hit["_source"]}
        for hit in hits
    ]
    #   Fusionne l'identifiant du document (_id, propre à Elasticsearch) avec son contenu (_source, les champs normalisés indexés)
    #    pour produire un objet plat et cohérent avec ce que l'endpoint d'ingestion retourne déjà à la création d'un log.
    return {"total": total, "page": page, "page_size": page_size, "logs": logs}

async def get_log_by_id(es_client: AsyncElasticsearch, log_id: str) -> dict | None:
    """
    Récupère un log précis par son identifiatn Elasticsearch.
    Retourne None si aucun document ne correspond à cet identifiant, plutôt que de lever une exception; c'est à l'appelant
     (le router HTTP) de décider comment traduire cette absence en réponse HTTP (généralement un code 404).
    """
    try:
        response = await es_client.get(
            index=settings.es_logs_index_name,
            id=log_id,
        )
    except Exception:
        #   Le client elasticsearch.py lève une exception (NotFoundError) quand l'identifiant demandé n'existe pas dnas l'index.
        #   On la copture ici pour la traduire en un retour None simple, que le router pourra transformer en réponse 404 propre.
        return None
    
    return {"id": response["_id"], **response["_source"]}