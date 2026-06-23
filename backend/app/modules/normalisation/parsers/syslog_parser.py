#   backend/app/modules/normalisation/parsers/syslog_parser.py
#
#   Ce fichier implémente la lecture du format Syslog RFC3164, 
#    le format historique le plus répendu, utilisé par Linux, 
#    Cisco et beaucoup d'équipements réseau.
#
#   Exemple de message brut RFC3164 typique:
#    "<34>Oct 11 22:14:15 mymachine sshd[1234]: Failed password for root from 192.168.1.50"
#
#   Décomposition de cette chaîne:
#       <34>                ->  Code de priorité (combine "facility" et "severity" du protocol Syslog;
#                                   non utilisé dans notre traitement actuel)
#       Oct 11 22:14:15     ->  Date et heure, sans année (particularité historique du format RFC3164)
#       mymachine           ->  Nom de la machine émettrice (hostname)
#       sshd[1234]          ->  Nom du processus émetteur et son numéro
#       Failed password...  ->  Message applicatif réel

import re
from datetime import datetime, timezone

from app.modules.normalisation.parsers.base import LogParser, ParsedLog

class SyslogRFC3164Parser(LogParser):
    """
    Analyseur syntaxique pour les messages au format Syslog RFC3164
    """

    #   Expression régulière qui capture les blocs qui mous interessent dans un message Syslog RFC3164.
    #   Elle est compilée une seule fois au niveau de la classe car re.compile() a un coût en performance
    #    et ce parser peut être appelé très fréquemment en conditions réelles.
    _PATTERN = re.compile(
        r"^<(?P<priority>\d+)>"             #   <34>        ->  groupe "priority"
        r"(?P<month>\w{3})\s+"              #   Oct         ->  groupe "month"
        r"(?P<day>\d{1,2})\s+"              #   11          ->  groupe "day"
        r"(?P<time>\d{2}:\d{2})\s+"         #   22:14:15    ->  groupe "time"
        r"(?P<host>\S+)\s+"                 #   mymachine   ->  groupe "host"
        r"(?P<message>.*)$"                 #   Tout le reste du message
    )

    #   La syntaxe (?<nom>...) crée un "groupe nommé" dans l'expression régulière. 
    #   On peut ensuite récupérer chaque portion capturée via match.group("nom"),
    #    rendant le code plus lisible que le sportions numériques (group(1), (group(2)...).

    def can_handle(self, source: str) -> bool:
        """
        Ce parser se déclare compétent pour 2 origines de transport:
            "syslog" (logs transmis via le récepteur Syslog de l'infra);
            "agent_linux" qui est un agent déployé qui réutiliserait le même format texte.
        """
        return source in {"syslog", "agent_linux"}
    
    def parse(self, raw_message: str) -> ParsedLog:
        """
        Analyse un message brut au format Syslog RFC3164 et retourne ses champs structurés.
        Lève une ValueError si le message ne correspond pas au format attendu.
        """
        match = self._PATTERN.match(raw_message)

        if match is None:
            #   Le message ne correspond pas au format attendu: On lève une erreur explicite que de
            #    deviner ou renvoyer des champs vides.
            #   Un rejet propre et visible est préférable à un log silencieusement mal interprété.
            raise ValueError(f"Message non conforme au format Syslog RFC3164: {raw_message!r}")
        
        groups = match.groupdict()

        #   Le format RFC3164 ne contient pas l'année dans le timestamp (limitation historiqeu du protocol).
        #   Déduisons la donc nous-même vue que le log doit appartenir à l'année en cours de traitement
        current_year = datetime.now(timezone.utc).year
        timestamp_str = (f"{current_year} {groups['month']} {groups['day']} {groups['time']}")

        #   strptime avec le motif "%b" reconnait les abréviations de mois anglaises, cohérent avec le format Syslog standard
        timestamp = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")

        #   strptime() produit toujours un datetime "naïf" (sans fuseau horaire attaché),
        #    même en cas d'usage de l'heure UTC pour déduction de l'année.
        #   Pour rester cohérent avec le mapping Elasticsearch attendant un format de date avec fuseau horaire.
        timestamp = timestamp.replace(tzinfo=timezone.utc)

        #   Extraction de l'adresse IP source: Le format RFC3164 ne le fournit pas dans un champ dédié.
        #   Elle est souvent intégrée dans le texte du message applicatif lui-même
        #    (par exemple "Failed password ... from 192.168.1.50").
        #   On la cherche avec une expression régulière simple dans cette portion du message.
        ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", groups["message"])
        source_ip = ip_match.group(1) if ip_match else "0.0.0.0"            #   Valeur de replique explicite au lieu de None, afin que le champ source_ip soit toujours exploitable dans les futures requêtes de filtrage et corrélation sans gestion de cas empty dans le code

        return ParsedLog(
            timestamp=timestamp,
            source_ip=source_ip,
            host=groups["hosts"],
            raw_message=raw_message,
            tags=[],                        #   Le format RFC3164 ne contient jamais de champs "tags". Il n'existe que pour les logs arrivant déjà en JSON.
                                            #    on fournit donc une liste vide ici, cohérent avec default_value de déclarée dans ParsedLog et nécessaire 
                                            #    pour que la construction de cet objet n'échoue jamais à cause de son absence.
        )
        #   Message brute original conservé en entier (pas seulement la portion applicative), ce qui est nécessaire 
        #    pour la valeur probatoire et forensique des logs