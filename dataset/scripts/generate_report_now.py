#!/usr/bin/env python3
"""
Déclenchement manuel de la génération de rapports — Smart SIEM DATA S3.

Usage :
    python scripts/generate_report_now.py --type daily
    python scripts/generate_report_now.py --type weekly
    python scripts/generate_report_now.py --type custom \\
        --date-from 2026-06-01T00:00:00Z --date-to 2026-06-19T23:59:59Z
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.reports.scheduler import run_daily_report, run_weekly_report
from app.reports.pdf_generator import generate_pdf_report

GREEN = "\033[92m"
RED   = "\033[91m"
BOLD  = "\033[1m"
RESET = "\033[0m"


def main():
    parser = argparse.ArgumentParser(
        description="Génère un rapport PDF Smart SIEM manuellement.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--type",
        required=True,
        choices=["daily", "weekly", "custom"],
        help="Type de rapport à générer.",
    )
    parser.add_argument(
        "--date-from",
        metavar="ISO8601",
        help="Date de début (requis pour --type custom). Ex: 2026-06-01T00:00:00Z",
    )
    parser.add_argument(
        "--date-to",
        metavar="ISO8601",
        help="Date de fin   (requis pour --type custom). Ex: 2026-06-19T23:59:59Z",
    )
    args = parser.parse_args()

    print(f"\n{BOLD}Smart SIEM — Génération manuelle de rapport{RESET}")
    print("─" * 50)

    try:
        if args.type == "daily":
            print("Type  : quotidien (J-1)")
            result = run_daily_report()

        elif args.type == "weekly":
            print("Type  : hebdomadaire (7 derniers jours)")
            result = run_weekly_report()

        else:  # custom
            if not args.date_from or not args.date_to:
                parser.error("--date-from et --date-to sont requis pour --type custom.")
            print(f"Type  : personnalisé")
            print(f"Du    : {args.date_from}")
            print(f"Au    : {args.date_to}")
            result = generate_pdf_report(args.date_from, args.date_to)

        print()
        print(f"{GREEN}✓ Rapport généré avec succès{RESET}")
        print(f"  Fichier      : {result['path']}")
        print(f"  SHA-256      : {result['sha256']}")
        print(f"  Généré le    : {result['generated_at']}")

    except Exception as exc:
        print(f"\n{RED}✗ Erreur : {exc}{RESET}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
