#   backend/app/api/v1/routers/reports.py
#
#   Ce fichier définit les endpoints liés aux rapports de sécurité : génération, listing, téléchargement.
#
#   *** ARCHITECTURE : ISOLATION PAR SOUS-PROCESSUS ***
#   Le backend (package Python "app" dans backend/app/) et le module data (package Python "app" dans
#    dataset/app/) portent le MÊME nom de package. Un import direct depuis ce fichier
#    (ex: "from app.reports.pdf_generator import ...") résoudrait vers backend/app et non dataset/app,
#    ou casserait sys.modules si les deux sont importés dans le même process.
#   Solution : les fonctions du dataset sont exécutées dans un SOUS-PROCESSUS Python dédié, où seul
#    dataset/ est sur sys.path. Aucun fichier du dataset n'est modifié ; ils sont exécutés tels quels,
#    exactement comme s'ils étaient lancés en CLI depuis dataset/.

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.modules.rbac.roles import require_role

router = APIRouter(prefix="/api/reports", tags=["reports"])

#   ── Chemins ──────────────────────────────────────────────────────────────────
#   Ce fichier est à backend/app/api/v1/routers/reports.py ; la racine du projet est 5 niveaux au-dessus.
_PROJECT_ROOT = Path(__file__).resolve().parents[5]
_DATASET_DIR  = _PROJECT_ROOT / "dataset"
_REPORTS_DIR  = _DATASET_DIR / "reports"          #   Cohérent avec _REPORTS_DIR de pdf_generator.py/scheduler.py

_SUBPROCESS_TIMEOUT_SECONDS = 120


#   ── Modèles ──────────────────────────────────────────────────────────────────
class ReportGenerateRequest(BaseModel):
    """
        Corps de la requête de génération d'un rapport PDF.
        type="daily"/"weekly" : aucune date requise, calculées automatiquement (J-1 / 7 derniers jours).
        type="custom"         : date_from et date_to obligatoires (ISO 8601, ex: "2026-06-01T00:00:00Z").
    """
    type:       Literal["daily", "weekly", "custom"]
    date_from:  str | None = None
    date_to:    str | None = None


#   ── Exécution isolée dans le dataset ────────────────────────────────────────
async def _run_in_dataset(inline_script: str, *args: str) -> dict:
    """
        Exécute `inline_script` dans un sous-processus Python dont le seul répertoire ajouté à sys.path
         est dataset/ (jamais backend/), pour que "import app.reports...." résolve vers dataset/app/reports/...
         sans jamais toucher au package "app" du backend.
        `inline_script` doit imprimer un unique objet JSON sur stdout en cas de succès.
        Lève HTTPException (503 si Elasticsearch/dataset indisponible, 500 sinon) en cas d'échec.
    """
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-c", inline_script, *args,
        cwd=str(_DATASET_DIR),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=_SUBPROCESS_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError:
        process.kill()
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="La génération du rapport a dépassé le délai imparti.",
        )

    if process.returncode != 0:
        error_text = stderr.decode("utf-8", errors="replace").strip()
        #   Distingue une panne d'infrastructure (Elasticsearch injoignable) d'une erreur de script.
        if "ConnectionError" in error_text or "Elasticsearch" in error_text:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Elasticsearch indisponible pour le module data : {error_text[-500:]}",
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Échec de la génération du rapport : {error_text[-500:]}",
        )

    try:
        return json.loads(stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Sortie inattendue du script de génération : {stdout[-500:]!r}",
        ) from exc


#   Scripts inline : importent les fonctions RÉELLES du dataset (aucune duplication de logique),
#    ne font qu'ajouter dataset/ à sys.path puis appeler la fonction déjà existante et fiable.
_DAILY_SCRIPT = (
    "import sys, json; sys.path.insert(0, '.'); "
    "from app.reports.scheduler import run_daily_report; "
    "print(json.dumps(run_daily_report()))"
)

_WEEKLY_SCRIPT = (
    "import sys, json; sys.path.insert(0, '.'); "
    "from app.reports.scheduler import run_weekly_report; "
    "print(json.dumps(run_weekly_report()))"
)

_CUSTOM_SCRIPT = (
    "import sys, json; sys.path.insert(0, '.'); "
    "from app.reports.pdf_generator import generate_pdf_report; "
    "result = generate_pdf_report(sys.argv[1], sys.argv[2]); "
    "print(json.dumps(result))"
)


#   ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("", summary="Liste des rapports PDF déjà générés")
async def get_all_reports(user: dict = Depends(require_role("analyst"))):
    """
        Retourne la liste des rapports PDF présents sur disque (dataset/reports/, y compris
         les sous-dossiers daily/ et weekly/), du plus récent au plus ancien.
        Rôle requis : analyst ou plus.
        Ne nécessite AUCUNE exécution côté dataset : simple lecture du système de fichiers.
    """
    if not _REPORTS_DIR.exists():
        return {"total": 0, "reports": []}

    files = sorted(
        _REPORTS_DIR.rglob("*.pdf"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    reports = [
        {
            "filename":     f.name,
            "relative_path": str(f.relative_to(_REPORTS_DIR)),
            "category":     f.parent.name if f.parent != _REPORTS_DIR else "custom",
            "size_bytes":   f.stat().st_size,
            "modified_at":  datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat(),
        }
        for f in files
    ]

    return {"total": len(reports), "reports": reports}


@router.post("/generate", status_code=status.HTTP_201_CREATED, summary="Génère un nouveau rapport PDF")
async def generate_report(
    body: ReportGenerateRequest,
    user: dict = Depends(require_role("administrator")),
):
    """
        Déclenche la génération d'un rapport PDF via le module data (dataset/app/reports/), exécuté
         dans un sous-processus isolé pour éviter toute collision de package avec le backend.
        Rôle requis : administrator.
        type="daily"/"weekly" : pas de dates à fournir, calculées automatiquement.
        type="custom"         : date_from et date_to obligatoires.
    """
    if body.type == "daily":
        result = await _run_in_dataset(_DAILY_SCRIPT)

    elif body.type == "weekly":
        result = await _run_in_dataset(_WEEKLY_SCRIPT)

    else:  # custom
        if not body.date_from or not body.date_to:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="date_from et date_to sont requis pour type='custom'.",
            )
        result = await _run_in_dataset(_CUSTOM_SCRIPT, body.date_from, body.date_to)

    return {
        "status":       "rapport généré",
        "type":         body.type,
        "generated_by": user["username"],
        **result,   #   path, sha256, generated_at — tels que retournés par generate_pdf_report()
    }


@router.get("/{relative_path:path}/download", summary="Télécharge un rapport PDF")
async def download_report(
    relative_path: str,
    user: dict = Depends(require_role("analyst")),
):
    """
        Télécharge un rapport PDF déjà généré, par son chemin relatif à dataset/reports/
         (ex: "daily/siem_report_....pdf", ou juste le nom de fichier pour un rapport custom).
        Rôle requis : analyst ou plus.
    """
    candidate = (_REPORTS_DIR / relative_path).resolve()

    #   Protection anti path-traversal : le chemin résolu doit rester strictement à l'intérieur
    #    de dataset/reports/, même si l'appelant tente d'injecter "../../.env" par exemple.
    if _REPORTS_DIR.resolve() not in candidate.parents and candidate != _REPORTS_DIR.resolve():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Chemin invalide.")

    if not candidate.exists() or candidate.suffix != ".pdf":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rapport introuvable : '{relative_path}'.",
        )

    return FileResponse(
        path=str(candidate),
        media_type="application/pdf",
        filename=candidate.name,
    )