# Restreindre le transfert rsyslog vers le SIEM (auth/authpriv/kern uniquement)

Copie-colle ce bloc entier dans ton terminal :

```bash
sudo tee /etc/rsyslog.d/60-siem-forward.conf > /dev/null <<'CONF'
auth,authpriv,kern.*  @127.0.0.1:5140
CONF

sudo systemctl restart rsyslog
```

Puis vérifie que ça a bien pris :

```bash
sudo systemctl status rsyslog --no-pager | head -5
cat /etc/rsyslog.d/60-siem-forward.conf
```
