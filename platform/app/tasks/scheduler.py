"""Periodic re-scan of verified domains.

In-process APScheduler is used here for local dev/demo convenience only.
The production deployment (platform/k8s/cronjob-scan.yaml) runs scans as
Kubernetes CronJobs instead - one-shot pods on a schedule, independently
scalable and restartable per domain, rather than a scheduler thread living
inside the API process. This module is what that CronJob's container
entrypoint calls (`python -m app.tasks.scheduler --once`), so the same
logic backs both the local-dev scheduler and the production CronJob.
"""

from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import SessionLocal
from app.models import Domain, ScanType
from app.services.scan_runner import run_scan

logger = logging.getLogger(__name__)


def scan_all_verified_domains(db: Session) -> None:
    domains = db.query(Domain).filter(Domain.verified_at.isnot(None)).all()
    logger.info("Re-scanning %d verified domain(s)", len(domains))
    for domain in domains:
        owner_email = domain.owner.email if domain.owner else None
        for scan_type in (ScanType.SUBDOMAINS, ScanType.TLS):
            try:
                run_scan(db, domain, scan_type, owner_email=owner_email)
            except Exception:
                logger.exception("Scheduled scan %s failed for %s", scan_type, domain.name)


def run_once() -> None:
    db = SessionLocal()
    try:
        scan_all_verified_domains(db)
    finally:
        db.close()


def start_background_scheduler() -> BackgroundScheduler:
    settings = get_settings()
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_once,
        "interval",
        hours=settings.scan_interval_hours,
        id="rescan-verified-domains",
    )
    scheduler.start()
    return scheduler


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_once()
