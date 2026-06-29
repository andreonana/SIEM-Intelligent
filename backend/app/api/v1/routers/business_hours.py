#   backend/app/api/v1/routers/business_hours.py
#
#   Ce ichier expose les endpoints de configuration des horaires de travail de l'entreprise.

from fastapi import APIRouter, Depends, HTTPException, status
from elasticsearch import AsyncElasticsearch
from pydantic import BaseModel

from app.db.elasticsearch_client import get_es_client
from app.modules.rbac.roles import require_role
from app.modules.correlation.business_hours_service import get_business_hours_config, update_business_hours_config, add_exception

router = APIRouter(prefix="/api/business-hours", tags=["business-hours"])

class BusinessHoursUpdateRequest(BaseModel):
    """
        Corps de la requête de configuration des horaires de travail normaux.
    """

    working_days:   list[int]                                                   #   0 = lundi ... 6 = dimanche
    opening_time:   str                                                         #   Format "HH:MM"
    closing_time:   str                                                         #   Format "HH:MM"

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

@router.get("")
async def get_config(es_client: AsyncElasticsearch = Depends(get_es_client), user: dict = Depends(require_role("reader")),):
    """
        Retourne la configuration actuelle des horaires de travail.
        Rôle requis: reader ou plus
    """
    return await get_business_hours_config(es_client)

@router.put("")
async def update_config(
    body: BusinessHoursUpdateRequest,
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user: dict = Depends(require_role("administrator")),
):
    """
        Conigure les horaires de travail normaux de l'entreprise.
        Rôle requis: administrateur ou plus.
    """
    return await update_business_hours_config(
        es_client,
        working_days=body.working_days,
        opening_time=body.opening_time,
        closing_time=body.closing_time,
    )

@router.post("/exceptions", status_code=status.HTTP_201_CREATED)
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
        return await add_exception(
            es_client,
            exception_date=body.date,
            opening_time=body.opening_time,
            closing_time=body.closing_time,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc