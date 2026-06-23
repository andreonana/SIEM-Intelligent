"""
Planificateur de rapports périodiques — Smart SIEM Module DATA, Semaine 3.

Importable par le Backend :
    from app.reports.scheduler import start_scheduler

Lancement autonome :
    python -m app.reports.scheduler
"""

import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

_BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(_BASE_DIR / ".env")
sys.path.insert(0, str(_BASE_DIR))

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

from app.reports.pdf_generator import generate_pdf_report

_REPORTS_DIR = Path(os.getenv("REPORTS_DIR", str(_BASE_DIR / "reports")))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("siem.scheduler")


def _iso(dt):
    """Retourne un datetime en chaîne ISO 8601 UTC."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def run_daily_report():
    """
    Génère le rapport PDF de la dernière journée (J-1, 00:00:00 → 23:59:59 UTC).

    Le fichier est sauvegardé dans reports/daily/.

    Retour
    ------
    dict — résultat de generate_pdf_report() :
        {"path": str, "sha256": str, "generated_at": str}

    Exemple
    -------
    >>> result = run_daily_report()
    >>> print(result["path"])
    /…/reports/daily/siem_report_2026-06-22T00-00-00Z_2026-06-22T23-59-59Z.pdf
    """
    now       = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=1)
    date_from = _iso(yesterday.replace(hour=0,  minute=0,  second=0,  microsecond=0))
    date_to   = _iso(yesterday.replace(hour=23, minute=59, second=59, microsecond=0))

    output_dir = _REPORTS_DIR / "daily"
    output_dir.mkdir(parents=True, exist_ok=True)

    safe_from = date_from.replace(":", "-")
    safe_to   = date_to.replace(":", "-")
    output_path = output_dir / f"siem_report_{safe_from}_{safe_to}.pdf"

    log.info("Génération rapport quotidien : %s → %s", date_from, date_to)
    result = generate_pdf_report(date_from, date_to, output_path=output_path)
    log.info("Rapport quotidien généré : %s (sha256: %s…)", result["path"], result["sha256"][:12])
    return result


def run_weekly_report():
    """
    Génère le rapport PDF des 7 derniers jours (lundi J-7 00:00:00 → dimanche J-1 23:59:59 UTC).

    Le fichier est sauvegardé dans reports/weekly/.

    Retour
    ------
    dict — résultat de generate_pdf_report() :
        {"path": str, "sha256": str, "generated_at": str}

    Exemple
    -------
    >>> result = run_weekly_report()
    >>> print(result["path"])
    /…/reports/weekly/siem_report_2026-06-16T00-00-00Z_2026-06-22T23-59-59Z.pdf
    """
    now       = datetime.now(timezone.utc)
    end       = now - timedelta(days=1)
    start     = now - timedelta(days=7)

    date_from = _iso(start.replace(hour=0,  minute=0,  second=0,  microsecond=0))
    date_to   = _iso(end.replace(  hour=23, minute=59, second=59, microsecond=0))

    output_dir = _REPORTS_DIR / "weekly"
    output_dir.mkdir(parents=True, exist_ok=True)

    safe_from = date_from.replace(":", "-")
    safe_to   = date_to.replace(":", "-")
    output_path = output_dir / f"siem_report_{safe_from}_{safe_to}.pdf"

    log.info("Génération rapport hebdomadaire : %s → %s", date_from, date_to)
    result = generate_pdf_report(date_from, date_to, output_path=output_path)
    log.info("Rapport hebdomadaire généré : %s (sha256: %s…)", result["path"], result["sha256"][:12])
    return result


def start_scheduler():
    """
    Démarre le planificateur APScheduler (bloquant) avec deux tâches :

    - run_daily_report()  : tous les jours à 00:05 UTC.
    - run_weekly_report() : tous les lundis à 00:10 UTC.

    Le scheduler est bloquant — cette fonction ne retourne pas.
    Pour un usage non-bloquant dans une application plus large,
    remplacer BlockingScheduler par BackgroundScheduler.

    Exemple
    -------
    >>> from app.reports.scheduler import start_scheduler
    >>> start_scheduler()   # bloque ici
    """
    scheduler = BlockingScheduler(timezone="UTC")

    scheduler.add_job(
        run_daily_report,
        trigger=CronTrigger(hour=0, minute=5, timezone="UTC"),
        id="daily_report",
        name="Rapport quotidien Smart SIEM",
        replace_existing=True,
    )

    scheduler.add_job(
        run_weekly_report,
        trigger=CronTrigger(day_of_week="mon", hour=0, minute=10, timezone="UTC"),
        id="weekly_report",
        name="Rapport hebdomadaire Smart SIEM",
        replace_existing=True,
    )

    log.info("Scheduler démarré — rapport quotidien à 00:05 UTC, hebdomadaire le lundi à 00:10 UTC.")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        log.info("Scheduler arrêté.")


if __name__ == "__main__":
    start_scheduler()
