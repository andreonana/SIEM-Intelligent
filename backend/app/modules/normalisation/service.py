#   backend/app/modules/normalisation/service.py
#
#   Ce fichier est la façade publique du module de normalisation.
#   C'est le seul fichier du module que les autres modules (en particulier celui d'ingestion) sont 
#    censé importer. Tout le reste de ce module (analyseurs syntaxiques et tagging) est un détail 
#    d'implémentation interne, invisible depuis l'extérieur du module.
#
#   Pourquoi cette règle compte concrètement :
#       Si la façon dont le ragging fonctionne est entièrement refaite demain ou si un troisième 
#        analyseur syntaxique est ajouté, acun autre module d'aura besoin de modification, tandis que
#        la signature de la fonction normalize() ci-dessous reste stable.
#
#   Principe d'encapsulation appliqué à l'échelle d'un module entier: 
#       Maintien de dépendance de données intermodulaire.

from dataclasses import dataclass
from datetime import datetime

from app.modules.normalisation.parsers.base import ParsedLog
from app.modules.normalisation.parsers.json_parser import JSONLogParser
from app.modules.normalisation.parsers.registry import parser_registry
from app.modules.normalisation.tagging import determine_log_type, determine_severity

@dataclass
class NormalizedLog:
    """
    Structure de données représentant un log entièrement normalisé et classifié, prêt à être stocké.
    Cette structure est distincte de ParsedLog définie car PasredLog est un détail interne des analyseurs
     syntaxique, alos que NormalizedLogs est ce que ce module retourne officiellement vers l'extérieur.
    Le module d'ingestion ne connait et n'utilise jamais ParsedLog directement.
    """

    timestamp: datetime
    source_ip: str
    host: str
    log_type: str
    severity: str
    raw_message: str
    tags: list[str]

def _classify_and_build(parsed: ParsedLog) -> NormalizedLog:
    """
    Applique la classification automatique (criticité et type) à un log déjà analysé, puis construit la structure 
     publique de ce module.
    Cette fonction privée est utilisée chez normalize() et normalize_json() qui ont des parties identiques pour éviter
     la redondance.
    """
    severity = determine_severity(parsed)
    log_type = determine_log_type(parsed)

    return NormalizedLog(
        timestamp=parsed.timestamp,
        source_ip=parsed.source_ip,
        host=parsed.host,
        log_type=parsed.log_type,
        severity=parsed.severity,
        raw_message=parsed.raw_message,
        tags=parsed.tags
    )

def normalize(raw_message: str, source: str) -> NormalizedLog:
    """
    Point d'entrée unique du module de normalisation.

    Prend un lessage de log brut et son origine de transport, et retourne un log entièrement normalisé
     et classifié: timestamp extrait et converti en objet datetime, adresse IP extraite, type fonctionnel
     et niveau de criticité déterminés.
    Cette fonction et la seule appelée par le module d'ingestion pour transformer un log brut en données
     structurées prêtes à être stockées.
    
    Lève une ValueError si le message ne peut pas être analyse correctement (format non reconnu, champ obligatoire
     manquant...).
    """
    #   Step 1: Selection automatique du bon analyseur syntaxique selon l'origine du log
    parser = parser_registry.get_parser_for(source)

    #   Step 2: Extraction des champs structurés à partir du texte brut.
    #   parsed est un ParsedLog - un détail interne, jamais retourné tel quel à l'appelant externe de cette fonction normalize()
    parsed = parser.parse(raw_message)

    #   Step 3: Classification et construction du réseau final, via _classify_and_build()
    return _classify_and_build(parsed)

def normalize_json(data: dict) -> NormalizedLog:
    """
    Point d'entrée alternatif dui module de normalisation, dédié aux logs reçuis sous forme d'obket JSON délà désérialisé (différent de string).
    Utilsée par l'endpoint dédié POST /app/v1/logs/ingest/json, pour les sources qui parlent déjà nativement, évitant ainsi à l'émetteur de devoir
     sérialiser son JSON en strings juste pour que ce module la redésérialise immédiatement après réception.
    Cette fonction est strictement équivalente à normalize() pour ce qui concerne la classification et la structure du résultat; seule l'étape 
     d'extraction change (appelle directement le parser JSON sur le dictionnaire déjà fourni, sans passer par le registre de parsers ni par un étape
     de désérialisation).
    Lève une ValueError si un cmp obligatoire est manquant dans le dictionnaire fourni.
    """
    #   On instancie directement le parser JSON, sans passer par le registre: Cette fonction est UNIQUEMENT destinée aux logs JSON natifs, 
    #    il n'ya donc pas d'ambiguïté sur le parser à utiliser, contrairement à normalize() ci-dessus qui doit choisir parmi plusieurs formats
    #    possibles selon la source.
    parser = JSONLogParser()
    parsed = parser.parse_dict(data)

    return _classify_and_build(parsed)