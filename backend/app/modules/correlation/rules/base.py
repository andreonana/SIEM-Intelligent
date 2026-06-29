#   backend/app/modules/correlation/rules/base.py
#
#   Ce fichier définit le contrat que toute règle de corrélation suit doit respecter, peu importe le motif précis qu'elle cherche (
#    seuil dépassé, séquence d'évènements, ...).
#   C'est le même principe architectural que LogParser lors de la normalisation de parsers.

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone

@dataclass
class CorrelationAlert:
    """
    Structure de données représentant une alerte produite par une règle de corrélation, avant son indexation dans Elasticsearch.
    Distincte du document final indexé tout comme ParsedLog l'est sur le log final.
    """
    
    #   Nom de la règle à l'origine de l'alerte (ex/ "bruteorce_threshold") permettant de tracer quelle règle est à l'origine de quelle
    #    alerte. Utile pour le débogage et l'affichage du dashboard
    rule_name:              str

    #   Niveau de criticité de l'alerte elle-même ("INFO", "WARNING", "HIGH" ou "CRITICAL"). C'est différent de la criticité d'un log individuel (
    #    "info"/"warning"/"critical"), déterminée par le tagging de normalisation.
    #   ATTENTION:  Une alerte de corrélation peut tout à fait être "CRITICAL" même si chaque log qui la compose est "warning" ou "info".
    severity:               str

    #   Description de ce qui a été détecté (exemple: "5 échecs d'authentification depuis 192.168.1.50 en 45 secondes").
    description:            str

    #   Identiication de la source concernée par l'alerte pour le module SOAR de cibler chaque action (blocage IP, isolation de machine) sur la bonne entité.
    source_ip:              str |   None = None
    host:                   str |   None = None

    #   Identiiants Elasticsearch de logs ayant déclenché cette alerte (traçabilité et ppreuves)
    related_logs_ids:       list[str] = field(default_factory=list)

    #   Horodatage de la détection elle-même (différent du timestamp des logs analysés), utoilisé pour mesurer la latence de détection
    detected_at:            datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    #   *** GENERATION D'UN LOG DE DETECTION DISTINCT   ***
    #   Certaines règles (ex. BruteforceRule) ne se contentent pas de produite une alerte de suici de l'index des alertes; elles doivent aussi 
    #    générer un nouveau log, distinct des logs individuels qui ont déclenché la détection, représentant la détection elle-même.
    #   Si generated_log_severity est renseigné, le moteur d'orchestration indexera ce log sup dans l'index des logs.
    generated_log_severity: str |   None = None
    generated_log_tags:     list[str]   =   field(default_factory=list)

    #   *** DECLENCHEMENT DE QUARANTAINE - DECIDE PAR REGLE ELLE-MEME   ***
    #   Indique si cette alerte doit déclencher le playbook de quarantaine sur les entités concernées (source_ip et/ou host de cette alerte).
    #   Ce champ est délibérément porté par chaque alerte elle-même au lieu de le déduire du moteur d'orchestration via ujne liste de noms en règle dur.
    triggers_lockout:       bool    =   False

@dataclass
class LogWindow:
    """
    Représente la fenêtre de logs récents que le moteur de corrélation fournit à chaque règle analyse.
    Cette classe encapsule la liste de logs (récuprée déjà Elasticsearch pour le moteur d'orchestration); car une règle ne sait jamais
     comment cette liste a été obtenue ni combien de temps elle couvre exactement, elle reçoit juste des documents à analyser.
    """

    #   Chaque élément est un document tel que retourné par les services d'ingestion lues;.
    logs:           list[str]

    window_start:   datetime
    window_end:     datetime

class CorrelationRule(ABC):
    """
    Classe abstraite déinissant l'interface commune à toutes les règles de corrélation.
    """

    @property
    @abstractmethod
    def name(str) -> str:
        """
        Nom court et unique de la règle, utilisé dans CorrelationAlert.rule_name pour traçer l'origine de chaque alerte produite.
        """
        ...
    
    @abstractmethod
    def evaluate(self, window: LogWindow) -> list[CorrelationAlert]:
        """
        Analyse la fenêtre de logs fournie et retourne la liste des alertes détectées (potentiellement vide si rien d'anormale n'est trouvé).
        Une règle peut retourner plusieurs alertes en un seul appel (ex. Plusieurs IP diverses dépassent le seuil de sécurité de brute-force dans
         la même fenêtre); d'où une liste en valeur de retour au lieu d'une alerte unique ou None.
        """
        ...