# Restreindre le transfert rsyslog vers le SIEM (auth/authpriv uniquement)

> **Mise à jour** : la facility `kern` a été retirée après test réel — elle
> transfère les refus AppArmor (`operation="ptrace"`, etc.), un bruit système
> extrêmement répétitif (164 969 logs quasi-identiques générés en quelques
> heures sur une seule machine, sans valeur de sécurité ici). Seules `auth` et
> `authpriv` sont pertinentes pour un usage SIEM (connexions, authentification).

Copie-colle ce bloc entier dans ton terminal :

```bash
sudo tee /etc/rsyslog.d/60-siem-forward.conf > /dev/null <<'CONF'
auth,authpriv.*  @127.0.0.1:5140
CONF

sudo systemctl restart rsyslog
```

Puis vérifie que ça a bien pris :

```bash
sudo systemctl status rsyslog --no-pager | head -5
cat /etc/rsyslog.d/60-siem-forward.conf
```

## Nettoyage du bruit kern déjà indexé (si tu avais appliqué l'ancienne règle)

```bash
docker exec siem-backend python3 -c "
from elasticsearch import Elasticsearch
from app.core.config import settings

es = Elasticsearch(hosts=[settings.elasticsearch_url])
resp = es.delete_by_query(
    index=settings.es_logs_index_name,
    body={'query': {'bool': {'filter': [
        {'term': {'host.keyword': '<TON_HOSTNAME>'}},
        {'term': {'log_type.keyword': 'système'}}
    ]}}},
    conflicts='proceed',
)
print('supprimés:', resp.get('deleted', 0))
"
```

Remplace `<TON_HOSTNAME>` par le résultat de `hostname` sur ta machine.
