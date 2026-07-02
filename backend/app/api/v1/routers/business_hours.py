#   backend/app/api/v1/routers/business_hours.py
#
#   Ce ichier expose les endpoints de configuration des horaires de travail de l'entreprise.

from unittest import result
from fastapi import APIRouter, Depends, HTTPException, status
from elasticsearch import AsyncElasticsearch
from pydantic import BaseModel

from app.db.elasticsearch_client import get_es_client
from app.modules.rbac.roles import require_role
from app.modules.correlation.business_hours_service import get_business_hours_config, remove_exception, update_business_hours_config, add_exception

router = APIRouter(prefix="/api/business-hours", tags=["business-hours"])

class BusinessHoursUpdateRequest(BaseModel):
    """
        Corps de la requête de configuration des horaires de travail normaux.
    """

    working_days:   list[int] = [0, 1, 2, 3, 4]                                             #   0 = lundi ... 6 = dimanche
    opening_time:   str       = "08:00"                                                     #   Format "HH:MM"
    closing_time:   str       = "20:00"                                                     #   Format "HH:MM"

class BusinessHoursExceptionRequest(BaseModel):
    """
        Corps de la requête d'ajout d'une exception ponctuelle pour une date précise.
        opening_time et closing_time redéfinissent librement l'horaire de cette date (réduction, extension, ouverture d'un
         jour normalement fermé).
        Aucune contrainte par rapport à l'horaire normal de la semaine. Une valeur None siginie "depuis/jusqu'au début/fin
         de la journée.
    """

    date:           str                                                         #   Format "YYYY-MM-DD"
    opening_time:   str |   None =  None                                        #   Format "HH:MM"
    closing_time:   str |   None =  None                                        #   Format "HH:MM"

@router.get("", summary="Horaires de travail configurés")
async def get_config(es_client: AsyncElasticsearch = Depends(get_es_client), user: dict = Depends(require_role("reader")),):
    """
        Retourne la configuration actuelle des horaires de travail.
        Rôle requis: reader ou plus
    """
    return await get_business_hours_config(es_client)

@router.put("", summary="Configurer les horaires de travail normaux")
async def update_config(
    body: BusinessHoursUpdateRequest,
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user: dict = Depends(require_role("administrator")),
):
    """
        Conigure les horaires de travail normaux de l'entreprise.
        Rôle requis: administrateur ou plus.
    """
    try:
        result = await update_business_hours_config(
            es_client,
            working_days=body.working_days,
            opening_time=body.opening_time,
            closing_time=body.closing_time,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc


@router.post("/exceptions", status_code=status.HTTP_201_CREATED, summary="Ajouter une exception ponctuelle (heure sup, jour exceptionnel)",)
async def create_exception(
    body: BusinessHoursExceptionRequest,
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user: dict = Depends(require_role("administrator")),
):
    """
        Ajoute une exception ponctuelle pour une date précise. Peut réduire, étendre ou ouvrir exceptionnellement un jour normalement
         fermé, selon la décision de l'admin.
         Rôle requis: administrateur ou plus.
    """
    try:
        result = await add_exception(
            es_client,
            exception_date=body.date,
            opening_time=body.opening_time,
            closing_time=body.closing_time,
        )
        return result
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc


@router.delete("/excetions/{exception_date}", summary="Supprimer une exception ponctuelle")
async def delete_exception(
    exception_date: str,
    es_client:      AsyncElasticsearch = Depends(get_es_client),
    user:           dict = Depends(require_role("administrator")),
):
    """
        Supprime l'exception ponctuelle d'une date précise. La date revient alors à l'horaire normale de la semaine.
        Rôle requis:    Administrator.
        Paramètre:
        exception_date: date au format "YYYY-MM-DD".
    """
    config = await get_business_hours_config(es_client)
    if exception_date not in config.get("exceptions", {}):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Aucune exception trouvée pour la date `{exception_date}`.",
        )
    result = await remove_exception(es_client, exception_date)
    return {"message": f"Exception du {exception_date} supprimée.", "config": result}