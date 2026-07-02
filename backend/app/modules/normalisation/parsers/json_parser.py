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
        
        return self.parse_dict(data, original_raw_message=raw_message)

    def parse_dict(self, data: dict, original_raw_message: str | None = None) -> ParsedLog:
        """
        Analyse un dictionnaire Python déjà désérialisé et retourne ses champs structurés.
        Utilisé directement par l'endpoint /ingest/json qui reçoit un objet JSON natif.
        Lève une ValueError si un champ obligatoire est manquant.
        """
        timestamp_raw = data.get("timestamp")
        if timestamp_raw is None:
            raise ValueError("Champ 'timestamp' manquant dans le JSON source.")

        if original_raw_message is not None:
            raw_message_to_store = original_raw_message
        else:
            raw_message_to_store = json.dumps(data, ensure_ascii=False)

        return ParsedLog(
            timestamp=datetime.fromisoformat(timestamp_raw),
            source_ip=data.get("source_ip", "0.0.0.0"),
            host=data.get("host", "unknown"),
            raw_message=raw_message_to_store,
            tags=data.get("tags", []),
        )