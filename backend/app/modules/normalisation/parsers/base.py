#   backend/app/modules/normalisation/parsers/base.py
#
#   Ce fichier défint le contrat que tout analyser syntaxique (parser) de logs 
#    doit respecter, peu importe le format prescris qu'il sait lire (Syslog, JSON,
#     ou un format futur comme pour AWS CloudTrail).
#
#   Un contrat commun plutôt que des fonctions séparrées sans interliaison car ça
#    permet au reste du code (registre de parsers, dans registry.py) de traiter 
#    n'importe quel parser de la même façon, via l'appel de sa méthode .parse(message)
#    sans besoin de connaissance des détails internes de chaque format de log.
#   Pour ajouter le support d'un nouveau format log, il suffira d'ajouter un nouvelle
#    classe respectant ce contrat, sans modifier le code existant.

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ParsedLog:
    """
    Strucuture de données intermédiaire produite par un analyseur syntaxique, avant
      l'étape de tagging (classification automatique en criticité et type) appliquée
      séparément, dans le fichier tagging.py de ce module.
      On sépare volontairement le rôle "lire un format" de celui "classifier le contenu":
      Un parser ne sait que transformer du texte brut en champs structurés, sans prise de
       décision de classification métier.
    """

    timestamp: datetime
    source_ip: str
    host: str
    raw_message: str
    tags: list[str]

class LogParser(ABC):
    """
    Classe abstraite définissant l'interface commune à tous les analyseurs syntaxique de logs.
    ABC = "Abstract Base Class": Classe jamais utilisable directement (erreur levée en cas 
     d'essaie de l'instancier), elle ne sert que de modèle que les classes filles doivent compléter.
    """

    @abstractmethod
    def can_handle(self, source: str) -> bool:
        """
        Indique si ce parser sait traiter des logs provenant de la source donnée ("syslog", "rest").
        Return True si ce parser est compétent pour cette source et False sinon.
        Cette méthode permet au registre de parser (registry.py) de choisir automatiquement le bon
         analyseur sans connaître à l'avance la liste de tous les parsers disponible.
        """
        ...

    @abstractmethod
    def parse(sefl, raw_message: str) -> ParsedLog:
        """
        Analyse un message brut et retourne les champs extraits sous forme structurée (ParseLog).
        Doit lever ValueErrour si le message ne correspond pas au format attendu par ce parser, 
         plutôt que de retourner des champs vides ou devinés - un rejet explicite est préférable à
          une interprétation silencieusement incorrecte, qui fausserait ensuite toute la suite du 
          traitement (corréaltion, recherche)
        """
        ...