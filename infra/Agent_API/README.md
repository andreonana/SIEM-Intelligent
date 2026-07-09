# AgentAPI - Playbook SOAR de blocage IP

AgentAPI est un petit service FastAPI installe sur une machine surveillee.
Son role est de recevoir un ordre du SIEM et de bloquer localement l'adresse IP
attaquante avec le pare-feu de la machine.

Cas principal:

1. Le SIEM detecte une attaque brute force SSH.
2. Le SIEM appelle `POST /block` sur l'AgentAPI.
3. L'AgentAPI valide la requete, l'IP et le token.
4. L'AgentAPI ajoute une regle pare-feu locale:
   - Windows: `netsh advfirewall`
   - Linux: `iptables`
5. L'action est journalisee dans `logs_audi/audit.jsonl`.

## Structure

```text
infra/Agent_API/
|-- main.py                 # Routes FastAPI
|-- models.py               # Schemas et validation des IPs
|-- security.py             # X-API-Key + whitelist IP appelante
|-- firewall.py             # Execution netsh/iptables
|-- state.py                # Etat local des IPs bloquees
|-- scheduler.py            # Actions differees en mode confirm
|-- audit.py                # Journal d'audit JSONL
|-- config.py               # Lecture du .env
|-- requirements.txt
|-- tests/
`-- logs_audi/
```

## Prerequis

### Windows

- Python 3.11+ ou 3.13
- PowerShell
- Droits administrateur pour creer/supprimer des regles firewall
- Port `9000` libre

Important: le serveur `uvicorn` doit etre lance dans un PowerShell
administrateur si tu veux tester un vrai blocage `netsh`.

### Linux

- Python 3.11+
- `iptables`
- Droits `root` ou service lance avec les permissions necessaires
- Port `9000` libre

## Installation

Depuis la racine du projet:

```powershell
cd infra/Agent_API
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Sous Linux:

```bash
cd infra/Agent_API
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration `.env`

Le fichier `.env` est a la racine du projet.

Exemple local Windows:

```env
AGENTAPI_TOKEN="my-secret-token"
AGENTAPI_ALLOWED_CALLERS="127.0.0.1"
AGENTAPI_HOST="127.0.0.1"
AGENTAPI_PORT="9000"
AGENTAPI_CONFIRM_DELAY=60
AGENTAPI_NEVER_BLOCK="127.0.0.1,::1"
AGENTAPI_LOG_DIR="D:\projet\Projet-Integrateur\SMART_SIEM\SIEM-Intelligent\infra\Agent_API\logs_audi"
```

Exemple en situation reelle:

```env
AGENTAPI_TOKEN="token-fort-partage-avec-le-siem"
AGENTAPI_ALLOWED_CALLERS="192.168.1.20"
AGENTAPI_HOST="0.0.0.0"
AGENTAPI_PORT="9000"
AGENTAPI_CONFIRM_DELAY=60
AGENTAPI_NEVER_BLOCK="127.0.0.1,::1,192.168.1.20,192.168.1.1"
```

Variables importantes:

| Variable | Role |
|---|---|
| `AGENTAPI_TOKEN` | Secret attendu dans le header `X-API-Key` |
| `AGENTAPI_ALLOWED_CALLERS` | IPs autorisees a appeler l'API, normalement le SIEM |
| `AGENTAPI_HOST` | Interface d'ecoute, `127.0.0.1` en local ou `0.0.0.0` en reseau |
| `AGENTAPI_PORT` | Port FastAPI, par defaut `9000` |
| `AGENTAPI_CONFIRM_DELAY` | Delai en secondes pour les actions en mode `confirm` |
| `AGENTAPI_NEVER_BLOCK` | IPs a ne jamais bloquer: SIEM, gateway, loopback |
| `AGENTAPI_LOG_DIR` | Dossier des logs d'audit et de l'etat local |

## Demarrage

### Windows, test reel firewall

Ouvrir PowerShell en administrateur:

```powershell
cd D:\projet\Projet-Integrateur\SMART_SIEM\SIEM-Intelligent\infra\Agent_API
.\.venv\Scripts\Activate.ps1
python -m uvicorn main:app --host 127.0.0.1 --port 9000
```

### Linux

```bash
cd infra/Agent_API
source .venv/bin/activate
sudo python -m uvicorn main:app --host 0.0.0.0 --port 9000
```

## Tests rapides

### Healthcheck

```powershell
Invoke-RestMethod http://127.0.0.1:9000/health
```

Reponse attendue:

```json
{
  "status": "ok",
  "os": "windows"
}
```

### Bloquer une IP de test

`8.8.8.8` est utile pour verifier que la regle firewall se cree.
Pour un test d'attaque reel, utilise l'IP de la machine attaquante.

```powershell
Invoke-RestMethod `
  -Method POST `
  -Uri http://127.0.0.1:9000/block `
  -Headers @{ "X-API-Key" = "my-secret-token" } `
  -ContentType "application/json" `
  -Body '{"attacker_ip":"8.8.8.8","incident_id":"test-1","reason":"test blocage"}'
```

Reponse attendue:

```json
{
  "results": [
    {
      "status": "executed",
      "ip": "8.8.8.8",
      "action_id": null,
      "detail": "IP attaquante bloquee"
    }
  ]
}
```

### Verifier la regle Windows

```powershell
netsh advfirewall firewall show rule name=AgentAPI_Block_8.8.8.8
```

### Debloquer

```powershell
Invoke-RestMethod `
  -Method POST `
  -Uri http://127.0.0.1:9000/unblock `
  -Headers @{ "X-API-Key" = "my-secret-token" } `
  -ContentType "application/json" `
  -Body '{"ip":"8.8.8.8","incident_id":"test-1","reason":"fin test"}'
```

## Test en situation reelle SSH brute force

Architecture recommandee:

```text
Machine SIEM       ---> POST /block ---> Machine AgentAPI
Machine attaquante ---> SSH/ping     ---> Machine AgentAPI
```

1. Sur la machine AgentAPI, configure `.env`:

```env
AGENTAPI_ALLOWED_CALLERS="IP_DU_SIEM"
AGENTAPI_HOST="0.0.0.0"
AGENTAPI_NEVER_BLOCK="127.0.0.1,::1,IP_DU_SIEM,IP_GATEWAY"
```

2. Lance l'API avec droits administrateur/root.

3. Depuis le SIEM, envoie l'ordre:

```bash
curl -X POST http://IP_AGENT:9000/block \
  -H "Content-Type: application/json" \
  -H "X-API-Key: token-fort-partage-avec-le-siem" \
  -d '{"attacker_ip":"IP_ATTAQUANT","incident_id":"bf-ssh-001","reason":"brute force ssh detecte"}'
```

4. Depuis la machine attaquante, teste l'acces:

```bash
ssh user@IP_AGENT
ping IP_AGENT
```

Selon l'OS et les regles firewall, le trafic depuis `IP_ATTAQUANT` doit etre
bloque.

## Validation des IPs

L'API refuse les IPs dangereuses ou non supportees avant d'appeler le pare-feu:

- IPv6, car le support Linux actuel utilise `iptables`, pas `ip6tables`
- `0.0.0.0`
- `255.255.255.255`
- loopback, par exemple `127.0.0.1`
- multicast
- link-local
- reserved
- toute IP presente dans `AGENTAPI_NEVER_BLOCK`
- toute IP presente dans `AGENTAPI_ALLOWED_CALLERS`

Cette double protection existe dans `models.py` et dans `firewall.py`.

## Endpoints

| Methode | Endpoint | Auth | Role |
|---|---|---|---|
| `GET` | `/health` | Non | Disponibilite simple |
| `POST` | `/block` | Oui | Bloque `attacker_ip` |
| `POST` | `/unblock` | Oui | Supprime une regle de blocage |
| `POST` | `/confirm/{action_id}/cancel` | Oui | Annule une action differee |
| `GET` | `/status` | Oui | Liste les IPs bloquees et actions en attente |
| `GET` | `/audit` | Oui | Lit les entrees recentes d'audit |

## Exemple body `/block`

```json
{
  "attacker_ip": "8.8.8.8",
  "incident_id": "inc-2026-07-05-001",
  "rule_id": "ssh-bruteforce",
  "reason": "5 echecs SSH en 60 secondes"
}
```

Avec une victime optionnelle en mode `confirm`:

```json
{
  "attacker_ip": "8.8.8.8",
  "victim_ip": "10.0.0.4",
  "victim_mode": "confirm",
  "incident_id": "inc-2026-07-05-002",
  "rule_id": "ssh-bruteforce",
  "reason": "Brute force SSH detecte"
}
```

## Audit et etat local

Les actions sont conservees ici:

```text
infra/Agent_API/logs_audi/audit.jsonl
infra/Agent_API/logs_audi/blocked_state.json
```

`audit.jsonl` contient une ligne JSON par action.
`blocked_state.json` contient les IPs que l'AgentAPI pense avoir bloquees.

## Tests unitaires

Depuis `infra/Agent_API`:

```powershell
.\.venv\Scripts\Activate.ps1
pytest
```

Si `pytest` n'est pas installe:

```powershell
pip install pytest httpx
pytest
```

## Depannage

| Probleme | Cause probable | Solution |
|---|---|---|
| `401 Unauthorized` | Header `X-API-Key` absent ou mauvais | Verifier `AGENTAPI_TOKEN` et le header |
| `403 Appelant non autorise` | IP source absente de `AGENTAPI_ALLOWED_CALLERS` | Ajouter l'IP du SIEM ou utiliser `127.0.0.1` en test local |
| `Commande echouee: netsh ... add rule` | Uvicorn pas lance en administrateur | Relancer PowerShell en administrateur |
| `Binaire introuvable: iptables` | Linux sans iptables | Installer iptables ou adapter `firewall.py` a nftables/ufw |
| IP refusee avec erreur 422 | IP non bloquable ou IPv6 | Utiliser une IPv4 attaquante valide |
| L'API demarre puis ne bloque rien | Droits systeme insuffisants | Verifier admin/root |

## Notes de securite

- Ne pas exposer cette API sur Internet.
- Utiliser un token fort pour `AGENTAPI_TOKEN`.
- Restreindre `AGENTAPI_ALLOWED_CALLERS` a l'IP du SIEM.
- Toujours mettre le SIEM et la gateway dans `AGENTAPI_NEVER_BLOCK`.
- En production, ajouter TLS ou placer l'API derriere un canal reseau de confiance.
