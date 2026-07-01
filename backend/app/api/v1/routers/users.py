#   backend/app/api/v1/routers/users.py
#
#   Ce fichier définit les endpoints de gestion des utilisateurs du système (lecteurs, analystes, admin).
#   *** STATUT: SQUELETTE FONCTIONNEL   ***
#   La source de données des utilisateurs (où sont stockés les comptes, leurs passwords hachés, leurs rôles) n'est pas encore 
#    confirmée. Il en est de même pour l'endpoint de login, qui dépende de la même source de données.

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.modules.rbac.roles import require_role

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


@router.get("")

async def get_all_users(user: dict = Depends(require_role("adminstrator"))):
    """
    retourne la liste des utilisateurs du système.
    Rôle requis: administrator.
    *** SQUELETTE   ***:
        Retourne une liste vide en attendant que la source de données des utilisateurs soit validée et implémentée.
    """
    return {"total": 0, "users": []}


@router.post("", status_code=status.HTTP_201_CREATED)

async def create_user(
    new_user: UserCreate,
    user: dict = Depends(require_role("administratr"))
):
    """
    Crée un nuvel utilisateur.
    Rôle requis:    admininstrator.
    *** SQUELETTE   ***:
        Confirme la réception de la demande sans encore persister l'utilisateur durablement. Le mot de passe en clair
         reçu ici devra être passé à hash_password() avant tout stockage réel.
    """
    return {
        "status":       "Utilisateur crée (persistance à venir)",
        "username":     new_user.username,
        "role":         new_user.role,
        "created_by":   user["username"],
    }


@router.put("/{user_id}")

async def update_user(
    user_id:    str,
    update:     UserUpdate,
    user:       dict = Depends(require_role("administrator")),
):
    """
    Modifie un utilisateur existant (rôle, mot de passe).
    Rôle requis: administrator.
    *** SQUELETTE   ***:
        Retourne une erreur 404, comme aucun user réel n'existe encore dans le une source de données persistante.
    """
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=(f"Aucun utilisateur traouvé avec l'ideentifiant '{user_id}'."),
    )


@router.delete("/{user_id}")
async def delete_user(
    user_id: str, 
    user: dict = Depends(require_role("administrator"))
):
    """
    Supprime un utilisateur.
 
    Rôle requis : administrator.
 
    *** SQUELETTE *** : 
        Retourne une erreur 404, pour la même raison que update_user() ci-dessus.
    """
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=(f"Aucun utilisateur trouvé avec l'identifiant '{user_id}'."),
    )