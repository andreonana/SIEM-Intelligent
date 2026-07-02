#   backend/app/modules/users/service.py
#
#   Service de gestion des utilisateurs du SIEM.
#   Chaque utilisateur est un document Elasticsearch dans l'index settings.es_users_index_name.
#   Le champ `username` est utilisé comme identifiant ES (_id) : unique, lookup O(1).
#
#   *** NOTE CONFIG ***
#   Ajouter dans backend/app/core/config.py (classe Settings) :
#       es_users_index_name: str = "smart-siem-users"
#
#   Structure d'un document utilisateur :
#   {
#       "username":        str,   (_id dans ES)
#       "hashed_password": str,
#       "role":            "reader" | "analyst" | "administrator",
#       "created_at":      ISO8601,
#       "created_by":      str,
#       "updated_at":      ISO8601 | None,
#       "updated_by":      str | None,
#   }

from datetime import datetime, timezone

from elasticsearch import AsyncElasticsearch, NotFoundError

from app.core.config import settings


# ─────────────────────────────────────────────────────────────────────────────
#   Rôles valides
# ─────────────────────────────────────────────────────────────────────────────
VALID_ROLES: frozenset[str] = frozenset({"reader", "analyst", "administrator"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
#   Lecture
# ─────────────────────────────────────────────────────────────────────────────
async def find_by_username(
    es_client: AsyncElasticsearch,
    username: str,
) -> dict | None:
    """
    Recherche un utilisateur par son username (= _id dans ES).
        Retourne None si introuvable.
    """
    try:
        response = await es_client.get(
            index=settings.es_users_index_name,
            id=username,
        )
        return {"id": response["_id"], **response["_source"]}
    except NotFoundError:
        return None
    except Exception:
        return None


async def get_user_by_id(
    es_client: AsyncElasticsearch,
    user_id: str,
) -> dict | None:
    """Alias de find_by_username (id == username dans ce modèle)."""
    return await find_by_username(es_client, user_id)


async def list_users(
    es_client: AsyncElasticsearch,
    page: int = 1,
    page_size: int = 50,
) -> dict:
    """
        Retourne la liste paginée des utilisateurs, triés par `username`.
        Ne retourne jamais le champ `hashed_password`.
    """
    from_offset = (page - 1) * page_size

    response = await es_client.search(
        index=settings.es_users_index_name,
        query={"match_all": {}},
        from_=from_offset,
        size=page_size,
        sort=[{"username": {"order": "asc"}}],
        _source_excludes=["hashed_password"],
    )

    total = response["hits"]["total"]["value"]
    users = [
        {"id": hit["_id"], **hit["_source"]}
        for hit in response["hits"]["hits"]
    ]

    return {"total": total, "page": page, "page_size": page_size, "users": users}


# ─────────────────────────────────────────────────────────────────────────────
#   Création
# ─────────────────────────────────────────────────────────────────────────────
async def create_user(
    es_client:       AsyncElasticsearch,
    username:        str,
    hashed_password: str,
    role:            str,
    created_by:      str,
) -> dict:
    """
        Crée un utilisateur dans ES.
        Lève ValueError si le username existe déjà ou si le rôle est invalide.
    """
    if role not in VALID_ROLES:
        raise ValueError(
            f"Rôle invalide : '{role}'. Valeurs acceptées : {sorted(VALID_ROLES)}."
        )

    existing = await find_by_username(es_client, username)
    if existing is not None:
        raise ValueError(f"Un utilisateur avec le username '{username}' existe déjà.")

    document = {
        "username":        username,
        "hashed_password": hashed_password,
        "role":            role,
        "created_at":      _now(),
        "created_by":      created_by,
        "updated_at":      None,
        "updated_by":      None,
    }

    await es_client.index(
        index=settings.es_users_index_name,
        id=username,          # username = _id → lookup O(1)
        document=document,
        refresh=True,
    )

    doc_out = dict(document)
    doc_out.pop("hashed_password", None)
    doc_out["id"] = username
    return doc_out


# ─────────────────────────────────────────────────────────────────────────────
#   Mise à jour
# ─────────────────────────────────────────────────────────────────────────────
async def update_user(
    es_client:       AsyncElasticsearch,
    username:        str,
    updated_by:      str,
    new_role:        str | None = None,
    hashed_password: str | None = None,
) -> dict | None:
    """
        Met à jour le rôle et/ou le mot de passe d'un utilisateur.
        Retourne None si l'utilisateur n'existe pas.
        Lève ValueError si le nouveau rôle est invalide.
    """
    existing = await find_by_username(es_client, username)
    if existing is None:
        return None

    if new_role is not None and new_role not in VALID_ROLES:
        raise ValueError(
            f"Rôle invalide : '{new_role}'. Valeurs acceptées : {sorted(VALID_ROLES)}."
        )

    patch: dict = {"updated_at": _now(), "updated_by": updated_by}
    if new_role is not None:
        patch["role"] = new_role
    if hashed_password is not None:
        patch["hashed_password"] = hashed_password

    await es_client.update(
        index=settings.es_users_index_name,
        id=username,
        doc=patch,
        refresh=True,
    )

    updated = await find_by_username(es_client, username)
    if updated:
        updated.pop("hashed_password", None)
    return updated


# ─────────────────────────────────────────────────────────────────────────────
#   Suppression
# ─────────────────────────────────────────────────────────────────────────────
async def delete_user(
    es_client: AsyncElasticsearch,
    username:  str,
) -> bool:
    """
        Supprime un utilisateur. Retourne True si supprimé, False si introuvable.
    """
    try:
        await es_client.delete(
            index=settings.es_users_index_name,
            id=username,
            refresh=True,
        )
        return True
    except NotFoundError:
        return False