#   backend/app/schemas/log.py
#
#   Ce fichier définit la forme que doivent avoir les données échangées avec l'API, et les valide automatiquement via Pydantic.
#   C'est la frontière entre le "monde extérieur" (infra qui envoie les logs) et la logique interne de l'application.
#
#   Architecture du flux de logs dans ce projet: 
#       C'est l'infra qui possède le récepteur Syslog et qui nous appelle avec un message brut. Le schéma RawLogIngrest 
#        ci-dessous représente exactement ce que l'infra nous envoie

from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, Field_validator

class RawLogIngest(BaseModel):
    """
    Schéma de la requête entrante sur l'endpoint d'ingestion de logs.
    Représente un log brut tel que transmis par le récepteur Syslog de l'infra, ou toute autre source REST directe.
    """

    #   model_config configure le comportement de validation Pydantic:
    #       - extra="forbid": L'appelant envoie un chmp JSON ou non déclaré ici, Pydantic lève une erreur au lieu de
    #        l'ignorer silencieusement. Ca permet de détecter immédiatement qu'un format de log inattendu est arrivé,
    #        plutôt que de perdre l'info sans le savoir.
    #       - str_strip_whitespace=True: retire automatiquement es espaces parasites en début et fin de chaînes,
    #        fréquents dans les logs Syslogs bruts.
    model_config = ConfigDict(extra="forbid", str_strip_whitesapce=True)

    raw_message: str = Field(
        min_length=1,
        description="La ligne de log brute, non parsée, telle que reçue.",
    )
    #   Field (min_length=1) refuse un message vide. Un log vide n'a aucune valeur d'iinvestigation et indiquerait
    #    un bug côté émetteur.

    source: str = Field(
        default="syslog",
        description=
        "Origine du transport : syslog, rest, agent_linux, agent-windows..."
    )
    #   Ne décrit pas le contenu du log lui-même, mais son canal source afin de choisir le bon analyseur syntaxique
    #    (parser) dans le module de normalisation, sans avoir à deviner le format uniquement depuis le contenu du message.

    @Field_validator("source")
    @classmethod
    def source_must_be_known(cls, value:str) -> str:
        """
        Vérifie que la valeur du champ "source" fait partie d'une liste de sources reconnues par le système.
        Si la valeur n'est pas reconnue, on lève une 'valueError' transformée automatiquement en réponse HTTP 42
         avec un message clair l'appelant
        """
        allowed = {"syslog", "rest", "agent_linux", "agent_windows"}
        if value not in allowed:
            raise ValueError(
                f"source inconnue: {value}. Valeurs acceptées: {allowed}"
            )
        
        return value

class NormalizedLogOut(BaseModel):
    """
    Schéma de la réponse sortante après traitement réussi d'un log.
    Représente le document JSON normalisé final, celui indexé dans Elasticsearch. C'est
     la confirmation renvoyée à l'appelant que le log a bien été traité et stocké.
    """

    #   from_attributes=True permet à Pydantic de construire cette réponse directement depuis un dictionnaire 
    #    Python ou d'un objet ayant ces attributs, sans convertion manuelle.
    model_config = ConfigDict(from_attribute=True)

    id: str
    timestamp: datetime
    source_ip: str
    host: str
    log_type: str
    severity: str
    raw_message: str

class BulkIngestResult(BaseModel):
    """
    Schéma de réponse pour l'endpoint d'ingestion en lot (bulk).
    Cet endpoint est un outil de développement et de test, utilisé pour charger rapidement un grand
      nombre de logs simulés sans devoir faire un requête HTTP/log.
    NE JAMAIS L'UTILSER DANS LE FLUX DE PRODUCTION REEL, qui reste strictement 1 APPEL HTTP = 1 LOG
    """

    total_received: int
    total_inserted: int
    total_ailed: int
    errors: list[str] = Field(default_factory=list)
    #   default_factory=list (et non default=[]): évite le piège classique en Python où une valeur
    #  par défaut (une liste) serait partagée entre toutes les instances de cette classe.