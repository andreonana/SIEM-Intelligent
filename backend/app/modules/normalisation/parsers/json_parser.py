#   backend/app/modules/normalisation/parsers/json_parser.py
#
#   Ce fichier gère le cas où une source envoie déjà un log structuré en JSON 
#    (par exemple une application REST personnalisée, ou plus tard une intégration avec AWS CloudTrail)
#   Deuxième format supporté par cette architecture de parsers interchangeables.
#   Ce parser expose deix endpoints:
#       - parse(raw_message: str): respecte le contrat commun de LogParser, utilisé quand le JSON arrive sous 
#                                   format string.
#       - parse_dict(data: dict): Variante acceptant directement un dictionnaire Python déjà sérialisé, sans repasser 
#                                   par json.loads(). Utilisé par l'endpoint dédié, qui accepte un véritable objet JSON
#                                   native de devoir sérialiser son log en chaîne de caractères juste pour que ce parser 
#                                   le redésérialise immédiatement après.
#   Les deux méthodes partagent exactement la même logique d'extraction de champs : parse() ne ait que désérialiser le string,
#    puis délègue à parser_dict() pour le reste du traitement. Aucune duplication de logique entre les deux chemins.

import json
from datetime import datetime

from app.modules.normalisation.parsers.base import LogParser, ParsedLog

class JSONLogParser(LogParser):
    """
    Analyyse syntaxique pour les logs déjà fournis sous forme de texte JSON, provenant d'une source directe de type REST.
    """

    def can_handle(self, source: str) -> bool:
        """
        Ce parser ne traite que les sources explicitement déclarées comme "rest"
        """
        return source == "rest"
    
    def parse(self, raw_message: str) -> ParsedLog:
        """
        Analyse une chaîne JSON et retourne ses champs structurés.
        Lève une ValueError si le contenu JSON n'est pas valide ou si un champ obligatoire manque
        """
        try:
            #   raw_message est un string contenant du JSON (pas directement un dictionnaire Python), car 
            #    le schéma RawLogIngest déclare ce champ comme un string - Cohérence de bout en bout entre 
            #    le contrat d'API et ce parser.
            data = json.loads(raw_message)
        except json.JSONDecodeError as exc:
            #   Transforme l'erreur technique de json.loads en erreur métier explicite (ValueError), cohérente
            #    avec celle des autres parsers.
            #   Ca simplifie la gestion d'erreurs dans le code appelant (toujours "ValueError" et jamais un type
            #    d'exception différent selon le parser utilisé).
            raise ValueError(f"JSON invalide reçu en source 'rest': {exc}") from exc
        
        #   Délégation à parse_dict() pour le reste du traitement : Le string a été désérialisée, on retome sur exactement
        #    la même logique d'extraction que pour un dictionnaire reçu directement.
        return self.parse_dict(data, original_raw_message=raw_message)

    def parse_dict(self, data: dict, original_raw_message: str | None = None) -> ParsedLog:
        """
        Analyse un dictionnaire Python déjà désérialisé et retourne ses champs structurés. Ce point d'entrée est utilisé directement
         par l'endpoint dédié, recevant déjà un objet JSON natif.
        Le paramètre original_raw_message permet de conserver le message brutal original tel qu'il a été reçu, sous forme
         de string, pour la valeur probatoire et forensique des logs. Si ce paramètre n'est pas fourni, on reconstruit une
         représentation textuelle du dictionnaire avec json.dumps, pour que le champ raw_message du log normalisé ne soit 
         jamais vide.
        Lève une ValueError si un champ obligatoire est manquant.
        """

        #   .get() avec une vlaeur par défaut évite qu'un champ manquant ne fasse planter tout le traitement avec 
        #    une KeyError, mieux un comportelent prévisible et documenté.
        timestamp_raw = data.get("timestamp")
        if timestamp_raw is None:
            raise ValueError("Champ 'timestamp' manquant dans le JSON source.")

        if original_raw_message is not None:
            raw_message_to_store = original_raw_message
        else:
            raw_message_to_store = json.dumps(data, ensure_ascii=False)
        
        return ParsedLog(
            #   fromisoformat attend un format de date au standard ISO 8601 (exemple "2026-06-20T14:30:00+00:00").
            #   C'est la convention à respecter par toute source qui nous envoie des logs en JSON direct.
            timestamp=datetime.fromisoformat(timestamp_raw),
            source_ip=data.get("source_ip", "0.0.0.0"),
            host=data.get("host", "unknown"),
            raw_message=raw_message_to_store,
            tags=data.get("tags", []),
        )