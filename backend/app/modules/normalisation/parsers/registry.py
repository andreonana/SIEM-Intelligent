#   backend/app/modules/normalisation/parsers/registry.py
#
#   Ce fichier fait le lien entre "quelle source m'envoie ce log" et "quel analyseur syntaxique (parser) dois-je utiliser pour le lire",
#    sans que le reste du code ait besoin de connaître la liste complète des parsers disponibles.
#
#   C'est un mécanisme rendant l'architecture extensible pour supporter un nouveau format de log plus tard
#    (format spécifique à AWS CloudTrail par exemple), il suffira d'ajouter une nouvelle classe de parser et l'enregistrer ici,
#    sans modifier aucun autre fichier.

from app.modules.normalisation.parsers.base import LogParser
from app.modules.normalisation.parsers.syslog_parser import SyslogRFC3164Parser
from app.modules.normalisation.parsers.json_parser import JSONLogParser

class ParserRegistry:
    """
    Registre central qui connaît tous les parsers disponible et sait en sélectionner le bon selon l'origine et le log entrant.
    """

    def __init__(self) -> None:
        #   Les parsers sont instancés une seule fois ici, au démarrafe de l'application, et non à chaque appel.
        #   Ils sont "sans état" (stateless), donc les réutiliser est sûr et évite un coût de création répété inutilement.
        self._parsers: list[LogParser] = [
            SyslogRFC3164Parser(),
            JSONLogParser(),
        ]

    def get_parser_for(self, source: str) -> LogParser:
        """
        Retourne le premier parser de la liste qui se déclare capable de traiter la source de donnée.
        Lève une ValueError si aucun parser ne convient, au lieu de retourner None (qui fraait planter le code plus loin, avec 
         un message d'erreru moins clair)
        """
        for parser in self._parsers:
            if parser.can_handle(source):
                return parser
            
        raise ValueError(f"Aucun parser disponible pour la source: {source}")
    
#   Instance unique partagée par toute l'application.
#   Le reste du code importe directement cette variable au lieu de créer une nouvelle instance de ParserRegistry à chaque utilisation.
parser_registry = ParserRegistry()