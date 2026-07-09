# backend/app/modules/alerting/notifier.py
#
# Module de notification des alertes : webhook Slack/Teams + email SMTP réel.
# V3 : envoi SMTP réel via aiosmtplib — aucun mode simulé.

from __future__ import annotations

import logging
from email.message import EmailMessage

import httpx

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Webhook Slack / Teams
# ---------------------------------------------------------------------------

async def send_webhook(url: str, payload: dict) -> bool:
    """Envoie une notification webhook (Slack / Teams). Retourne True si succès."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            return True
    except Exception as exc:
        logger.error("Webhook vers %s échoué: %s", url, exc)
        return False


# ---------------------------------------------------------------------------
# Email SMTP réel (aiosmtplib)
# ---------------------------------------------------------------------------

async def send_email(to: str, subject: str, body: str) -> bool:
    """
    Envoie un email via SMTP async (aiosmtplib).
    Utilise STARTTLS sur le port configuré.

    Variables .env requises :
      SMTP_HOST     — serveur SMTP (ex: smtp.gmail.com, mail.infomaniak.com)
      SMTP_PORT     — port (587 pour STARTTLS, 465 pour SSL)
      SMTP_USER     — adresse expéditrice + login
      SMTP_PASSWORD — mot de passe ou App Password
      ALERT_EMAIL_TO — destinataire par défaut (utilisé par notify_alert)

    Retourne True si succès, False si erreur (ne lève pas d'exception).
    """
    from app.core.config import settings

    if not settings.smtp_host:
        logger.warning("[Email] SMTP_HOST non configuré — email non envoyé vers %s.", to)
        return False

    if not settings.smtp_user:
        logger.warning("[Email] SMTP_USER non configuré — email non envoyé vers %s.", to)
        return False

    if not settings.smtp_password:
        logger.warning("[Email] SMTP_PASSWORD non configuré — email non envoyé vers %s.", to)
        return False

    try:
        import aiosmtplib

        msg = EmailMessage()
        msg["From"] = settings.smtp_user
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)

        # Détecter SSL vs STARTTLS selon le port
        use_tls = settings.smtp_port == 465
        start_tls = not use_tls  # STARTTLS sur 587 (ou tout port != 465)

        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user,
            password=settings.smtp_password,
            use_tls=use_tls,
            start_tls=start_tls,
            timeout=15.0,
        )
        logger.info("[Email] Email envoyé avec succès: to=%s subject=%r", to, subject)
        return True

    except Exception as exc:
        logger.error("[Email] Envoi échoué vers %s: %s", to, exc)
        return False


# ---------------------------------------------------------------------------
# Notification complète d'une alerte
# ---------------------------------------------------------------------------

async def notify_alert(alert, db: AsyncSession) -> None:
    """
    Envoie les notifications configurées pour une alerte.
    Ne lève pas d'exception si un canal est indisponible.
    """
    from app.core.config import settings
    from app.services.audit_service import log_action

    payload = {
        "text":        f"[SIEM ALERT] {alert.severity} — {alert.rule_name}",
        "alert_id":    alert.id,
        "severity":    alert.severity,
        "description": alert.description,
        "source_ip":   alert.source_ip,
        "mitre":       f"{alert.mitre_tactic} / {alert.mitre_technique}",
        "confidence":  getattr(alert, "confidence_score", None),
    }

    channels_notified = []

    if settings.slack_webhook_url:
        ok = await send_webhook(settings.slack_webhook_url, payload)
        if ok:
            channels_notified.append("slack")

    if settings.teams_webhook_url:
        ok = await send_webhook(settings.teams_webhook_url, payload)
        if ok:
            channels_notified.append("teams")

    if settings.alert_email_to:
        subject = f"[SIEM] {alert.severity} Alert: {alert.rule_name}"
        body = (
            f"Alert ID      : {alert.id}\n"
            f"Severity      : {alert.severity}\n"
            f"Confidence    : {getattr(alert, 'confidence_score', 'N/A')}%\n"
            f"Rule          : {alert.rule_name} ({alert.rule_id})\n"
            f"Description   : {alert.description}\n"
            f"Source IP     : {alert.source_ip or 'N/A'}\n"
            f"Host          : {getattr(alert, 'host', 'N/A')}\n"
            f"MITRE         : {alert.mitre_tactic} / {alert.mitre_technique}\n"
            f"Detected at   : {alert.detected_at}\n"
            f"SOAR status   : {getattr(alert, 'soar_status', 'N/A')}\n"
        )
        ok = await send_email(settings.alert_email_to, subject, body)
        if ok:
            channels_notified.append("email")

    await log_action(
        db=db,
        username="system",
        action="notification_send",
        target=str(alert.id),
        detail=f"channels={channels_notified}",
        result="success" if channels_notified else "no_channel",
    )
