#   backend/app/api/v1/routers/users.py
#
#   Ce fichier définit les endpoints de gestion des utilisateurs du système (lecteurs, analystes, admin).
#   *** STATUT: SQUELETTE FONCTIONNEL   ***
#   La source de données des utilisateurs (où sont stockés les comptes, leurs passwords hachés, leurs rôles) n'est pas encore 
#    confirmée. Il en est de même pour l'endpoint de login, qui dépende de la même source de données.

from elasticsearch import AsyncElasticsearch
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.db.elasticsearch_client import get_es_client
from app.modules.rbac.auth import hash_password
from app.modules.rbac.roles import require_role
from app.modules.users.service import VALID_ROLES, create_user, delete_user, get_user_by_id, list_users, update_user

router = APIRouter(prefix="/api/users", tags=["users"])

class UserCreate(BaseModel):
    """
        Corps de la requête de création dun utilisateur.
    """

    username:           str
    password:           str
    role:               str         #   "reader", "analyst" ou "administrator"

class UserUpdate(BaseModel):
    """
        Corps de la requette de modification d'un utilisateur existant.
    """

    role:               str | None = None
    password:           str | None = None


@router.get("", sumary="Liste des utilisateurs")

async def get_all_users(page: int = 1, page_size: int = 50, es_client: AsyncElasticsearch = Depends(get_es_client), user: dict = Depends(require_role("adminstrator"))):
    """
        retourne la liste des utilisateurs du système.
        Rôle requis: administrator.
        *** SQUELETTE   ***:
            Retourne une liste vide en attendant que la source de données des utilisateurs soit validée et implémentée.
    """
    try:
        return await list_users(es_client, page=page, page_size=page_size)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Elasticsearch indisponible: {exc}") from exc

@router.get("/{user_id}", summary="Détail d'un utilisateur")
async def get_user(
    user_id:   str,
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user:      dict = Depends(require_role("administrator")),
):
    """
        Retourne un utilisateur par son identifiant (= username).
        Rôle requis : administrator.
    """
    record = await get_user_by_id(es_client, user_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Utilisateur '{user_id}' introuvable.")
    record.pop("hashed_password", None)
    return record


@router.post("", status_code=status.HTTP_201_CREATED, summary="Créer un utilisateur")

async def create_new_user(
    new_user: UserCreate,
    es_client: AsyncElasticsearch = Depends(get_es_client),
    user: dict = Depends(require_role("administrator")),
):
    """
        Crée un nuvel utilisateur.
        Rôle requis:    admininstrator.
        *** SQUELETTE   ***:
            Confirme la réception de la demande sans encore persister l'utilisateur durablement. Le mot de passe en clair
            reçu ici devra être passé à hash_password() avant tout stockage réel.
    """
    if new_user.role not in VALID_ROLES:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"Rôle invalide: `{new_user.roole}`. Valeurs acceptées: {sorted(VALID_ROLES)}.")
    try:
        created = await create_user(
            es_client       = es_client,
            username        = new_user.username,
            hashed_password = hash_password(new_user.password),
            role            = new_user.role,
            created_by      = user["username"],
        )
        return created
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Elasticsearch indisponible: {exc}") from exc


@router.put("/{user_id}", summary="Modifier un utilisateur")

async def update_user(
    user_id:    str,
    update:     UserUpdate,
    es_client:  AsyncElasticsearch = Depends(get_es_client),
    user:       dict = Depends(require_role("administrator")),
):
    """
        Modifie un utilisateur existant (rôle, mot de passe).
        Rôle requis: administrator.
        *** SQUELETTE   ***:
            Retourne une erreur 404, comme aucun user réel n'existe encore dans le une source de données persistante.
    """
    hashed = hash_password(update.password) if update.password else None
    try:
        updated = await update_user(
            es_client       = es_client,
            username        = user_id,
            updated_by      = user["username"],
            new_role        = update.role,
            hashed_password = hashed,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Elasticsearch indisponible : {exc}") from exc
 
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Utilisateur '{user_id}' introuvable.")
    return updated


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Supprimer un utilisateur")
async def delete_user(
    user_id:    str, 
    es_client:  AsyncElasticsearch = Depends(get_es_client),
    user:       dict = Depends(require_role("administrator")),
):
    """
        Supprime un utilisateur.
    
        Rôle requis : administrator.
    
        *** SQUELETTE *** : 
            Retourne une erreur 404, pour la même raison que update_user() ci-dessus.
    """
    if user_id == user["username"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Un administrateur ne peut pas supprimer son propre compte.")
    deleted = await delete_user(es_client, user_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Utilisateur '{user_id}' introuvable.")
    