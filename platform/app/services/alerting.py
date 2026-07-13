"""Notify the domain owner when a scan detects a change worth their
attention. Two channels, both optional and independently configured -
a deployment with neither SMTP nor Slack configured just logs and skips,
rather than failing the scan itself (alerting is best-effort; the scan
result is already persisted regardless).
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

import httpx

from app.config import get_settings
from app.models import Finding

logger = logging.getLogger(__name__)


def _send_email(to_email: str, subject: str, body: str) -> None:
    settings = get_settings()
    if not settings.smtp_host:
        logger.info("SMTP not configured - skipping email alert to %s", to_email)
        return

    message = EmailMessage()
    message["From"] = settings.alert_from_email
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        smtp.starttls()
        if settings.smtp_username and settings.smtp_password:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)


def _send_slack(text: str) -> None:
    settings = get_settings()
    if not settings.slack_webhook_url:
        logger.info("Slack webhook not configured - skipping Slack alert")
        return

    response = httpx.post(settings.slack_webhook_url, json={"text": text}, timeout=10)
    response.raise_for_status()


def notify_finding(finding: Finding, owner_email: str) -> None:
    subject = f"[{finding.severity.value.upper()}] {finding.domain.name}: {finding.category}"
    body = (
        f"Domain: {finding.domain.name}\n"
        f"Category: {finding.category}\n"
        f"Severity: {finding.severity.value}\n"
        f"Detected: {finding.detected_at.isoformat()}\n\n"
        f"{finding.description}\n"
    )

    try:
        _send_email(owner_email, subject, body)
    except Exception:
        logger.exception("Failed to send email alert for finding %s", finding.id)

    try:
        _send_slack(f":rotating_light: {subject}\n{finding.description}")
    except Exception:
        logger.exception("Failed to send Slack alert for finding %s", finding.id)
