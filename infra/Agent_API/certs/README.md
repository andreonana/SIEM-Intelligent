# Certificats AgentAPI

Ce dossier n'est pas requis pour lancer l'AgentAPI en test local.

La version actuelle de l'agent fonctionne en HTTP simple:

```powershell
python -m uvicorn main:app --host 127.0.0.1 --port 9000
```

ou, en reseau de test:

```bash
python -m uvicorn main:app --host 0.0.0.0 --port 9000
```

Les scripts presents dans ce dossier sont conserves pour une future evolution
TLS/mTLS, mais ils ne sont pas utilises dans le workflow actuel.

Pour la securite actuelle, l'AgentAPI repose sur:

- le header `X-API-Key`
- la whitelist `AGENTAPI_ALLOWED_CALLERS`
- la liste de protection `AGENTAPI_NEVER_BLOCK`
- les droits administrateur/root necessaires au pare-feu

Avant d'activer TLS, documenter clairement:

1. l'autorite de certification utilisee;
2. le certificat serveur de chaque agent;
3. le certificat client du SIEM si mTLS est retenu;
4. le mode de rotation/revocation des certificats.
