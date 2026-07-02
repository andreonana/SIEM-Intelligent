"""
Serveur FastAPI minimal — démo de validation S2, Smart SIEM Module DATA.
Sert la page HTML de démonstration et expose deux endpoints JSON
qui délèguent directement aux fonctions search_logs() / get_timeline().

Lancement :
    cd dataset/
    uvicorn app.interface.server:app --reload
"""

import sys
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# Rend le package dataset/ importable quel que soit le répertoire de lancement
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from app.db.search import search_logs, get_timeline

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Smart SIEM — Démo DATA S2", docs_url="/docs")

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/api/search")
def api_search(
    source_ip: Optional[str] = Query(None),
    host:       Optional[str] = Query(None),
    log_type:   Optional[str] = Query(None),
    severity:   Optional[str] = Query(None),
    date_from:  Optional[str] = Query(None),
    date_to:    Optional[str] = Query(None),
    keyword:    Optional[str] = Query(None),
    page:       int           = Query(1, ge=1),
    page_size:  int           = Query(20, ge=1, le=200),
):
    """
    Appelle search_logs() avec les paramètres reçus et retourne le JSON.
    Tous les paramètres sont optionnels — comportement identique à la fonction.
    """
    try:
        return search_logs(
            source_ip=source_ip or None,
            host=host or None,
            log_type=log_type or None,
            severity=severity or None,
            date_from=date_from or None,
            date_to=date_to or None,
            keyword=keyword or None,
            page=page,
            page_size=page_size,
        )
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/timeline")
def api_timeline(
    source_ip: Optional[str]       = Query(None),
    host:      Optional[str]       = Query(None),
    date_from: Optional[str]       = Query(None),
    date_to:   Optional[str]       = Query(None),
    log_types: Optional[list[str]] = Query(None),
    max_events: int                = Query(500, ge=1, le=2000),
):
    """
    Appelle get_timeline() avec les paramètres reçus et retourne le JSON.
    log_types peut être répété : /api/timeline?log_types=auth&log_types=réseau
    """
    try:
        return get_timeline(
            source_ip=source_ip or None,
            host=host or None,
            date_from=date_from or None,
            date_to=date_to or None,
            log_types=log_types or None,
            max_events=max_events,
        )
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
