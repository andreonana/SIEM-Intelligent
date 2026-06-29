#   backend/app/modules/rbac/field_visibility.py
#
#   Ce fichier centralise la règle de visibilité des champs par rôle, distincte de la visibilité des endpoints eux-mêmes généré par 
#    require_role(). Un reader a le droit d'appeler les GET ou POST, mais ne doit voir, dans la réponse que les champs dorrespondant 
#    au résultat brut de la normalisation; jamais les métadonnées ajoutées par des étapes ultérieures du pipeline.
#
#   Cette liste est exprimée coimme une liste blanche de champs qui reste valide automatiqeument quand de nouveaux champs sont ajoutés
#    ailleurs dans li pipeline plus tard; un reader ne le verra jamais sans qu'on ait besoin de mettre à jour ce fichier à chaque nouvel
#    ajout. Avec une liste noire, il faudrait au contraire penser à ajouter chaque nouveau champ sensible à la liste, ce qui est plus 
#    fragile et plus facile à oublier.
#
#   Champ exacts produits par le module de normalisation. C'est la liste EXHAUSTIVE et UNIQUE de ce qu'un reader peut voir et filtrer
from pydoc import doc

from backend.app.modules.rbac import retention


NORMALIZATION_FIELDS = {
    "timestamp",
    "source_ip",
    "host",
    "log_type",
    "severity",
    "raw_message",
    "tags",
}

#   "extra" est volontairement ABSENT de cette liste; ce champ contient des données supplémentaires fournies par les agents sources, 
#    distinctes des champs stricts de ParsedLog. Un reader ne voit que le résultat de normalisation au sens strict.
def filter_document_for_role(document: dict, role: str) -> dict:
    """
        Filtre un document (log) pour ne garder que les champs visible par le rôle donné.
        Pour "analyst" et "administrator", retourne le document tel quel, sans filtrage (visibilité complète).
        Pour "reader", ne conserve que les clés présentes dans NORMALIZATION_FIELDS. Tout champ supplémentaire est silencieusement retiré.
    """
    if role in {"analyst", "administrator"}:
        return document

    return {key: value for key, value in document.items() if key in NORMALIZATION_FIELDS}

def filter_documents_for_role(documents: list[dict], role: str) -> list[dict]:
    """
        Applique filter_document_for_role() à une liste de documents.
    """
    return [filter_document_for_role(doc, role) for doc in documents]

def allowed_search_fields_for_role(role: str) -> set[str]:
    """
        Retourne l'ensemble des champs qu'un rôle donné est autorisé à utiliser comme critère de filtrage dans une recherche.
        Pour "reader", ce sont exactement les même champs que ceux visibles en sortie (NORMALIZED_FIELDS): il serait incohérent d'autoriser
         un reader à filter un champ qu'il ne peut même pas voir dans les résultats; celà permettrait de déduire indirectement la valeur d'un
         champ cahcé par essai successifs.
        Pour "analyst" et "administrator", retourne None pour signifier "aucune restriction" car tous les champs sont autorisés comme critère.
    """
    if role in {"analyst", "administrator"}:
        return None
    return NORMALIZATION_FIELDS