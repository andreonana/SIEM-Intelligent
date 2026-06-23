#   backend/app/core/config.py
#
#   Ce fichier centralise les réglages de comportement qui ne sont liées ni à la base de données,
#    ni à la sécurité , mais à la logique métier du module de normalisation des logs.
#
#   Toutes les valeurs sont lues depuis le fichier .env commun de l'équipe.
#
#   DEPENDANCES EXTERNES:
#       Variable concernée: CRITICAL_KEYWORDS attendue dans .env partagé à la racine du projet,
#        permettant de classer un log comme "critical" automatiquement si un mot clé apparaît, 
#        reajustable sans contact au code via une variable d'environnement séparé par des virgules.

from pydandic_settings import BaseSettings, SettingsConfifDict
#   BaseSettongs !== BaseModel est une classe spéciale de Pydantic v2 conçue pour lire
#       automatiquement les variables d'environnement et celles système, puis valider leur type.

class Settings(BaseSettings):

    #   --------    Paramètres de tagging automatique   --------
    #   Liste de keywords déclenchant un criticité "critical".
    critical_keywords: list[str] = [
        "failed password",
        "authentication failure",
        "denied",
    ]

    #   model_config configure comment Pydantic Settings lit les variables d'environnement.
    #       - env_file=".env" indique où se trouve le fichier .env partagé à la racine du projet backend.
    #       - extra="ignore" est essentiel car le fichier est partagé vue qu'il contient aussi des 
    #        variables utilisées par d'autres fichiers.
    #   Sans ce réglage, Pydantic lèverait une erreur de validation au démarrage dès qu'il 
    #    rencontre une variable du .env non expliqué explicitement comme champ de cette
    #    classe Settings précise.
    model_config = SettingsConfifDict(env_file=".env", extra="ignore")

#   Instance unique, importée partout où ces réglages sont nécessaires.
settings = Settings() 
