"""Orchestrates a single scan: run it, persist the result, diff against the
previous successful scan of the same type, raise Findings for anything
alert-worthy, and fire notifications. Kept separate from the routers so the
same orchestration can be triggered from an HTTP request (ad-hoc scan) or
from app/tasks/scheduler.py (periodic re-scan) without duplicating logic.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import Domain, Finding, ScanResult, ScanStatus, ScanType, Severity
from app.services import port_scan, subdomain_scan, tls_check
from app.services.alerting import notify_finding
from app.services.verification import require_verified

logger = logging.getLogger(__name__)


def _previous_successful_scan(db: Session, domain: Domain, scan_type: ScanType) -> ScanResult | None:
    return (
        db.query(ScanResult)
        .filter(
            ScanResult.domain_id == domain.id,
            ScanResult.scan_type == scan_type,
            ScanResult.status == ScanStatus.SUCCESS,
        )
        .order_by(ScanResult.started_at.desc())
        .first()
    )


def _raise_findings_for_subdomains(db: Session, domain: Domain, scan_result: ScanResult, diff: dict) -> list[Finding]:
    findings = []
    for host in diff["added"]:
        findings.append(
            Finding(
                domain_id=domain.id,
                scan_result_id=scan_result.id,
                category="new_subdomain",
                severity=Severity.MEDIUM,
                description=f"New subdomain discovered: {host}",
            )
        )
    db.add_all(findings)
    return findings


def _raise_findings_for_ports(db: Session, domain: Domain, scan_result: ScanResult, diff: dict) -> list[Finding]:
    findings = []
    for entry in diff["opened"]:
        findings.append(
            Finding(
                domain_id=domain.id,
                scan_result_id=scan_result.id,
                category="new_open_port",
                severity=Severity.HIGH,
                description=(
                    f"Port {entry['port']}/{entry['protocol']} is now open "
                    f"({entry.get('service') or 'unknown service'})"
                ),
            )
        )
    db.add_all(findings)
    return findings


def _raise_finding_for_tls(db: Session, domain: Domain, scan_result: ScanResult, result: dict) -> list[Finding]:
    if not result.get("expiring_soon"):
        return []
    finding = Finding(
        domain_id=domain.id,
        scan_result_id=scan_result.id,
        category="cert_expiring",
        severity=Severity.HIGH,
        description=(
            f"TLS certificate for {domain.name} expires in "
            f"{result['days_remaining']} day(s) ({result['expires_at']})"
        ),
    )
    db.add(finding)
    return [finding]


def run_scan(db: Session, domain: Domain, scan_type: ScanType, owner_email: str | None = None) -> ScanResult:
    """Run `scan_type` against `domain`, persist everything, return the
    ScanResult row. Never raises PermissionError to the caller for an
    unverified domain - it records a BLOCKED_UNVERIFIED result instead, so
    the attempt itself is auditable.
    """
    scan_result = ScanResult(domain_id=domain.id, scan_type=scan_type, status=ScanStatus.RUNNING)
    db.add(scan_result)
    db.commit()
    db.refresh(scan_result)

    try:
        require_verified(domain)
    except PermissionError as exc:
        scan_result.status = ScanStatus.BLOCKED_UNVERIFIED
        scan_result.error = str(exc)
        scan_result.finished_at = datetime.now(timezone.utc)
        db.add(scan_result)
        db.commit()
        return scan_result

    findings: list[Finding] = []
    try:
        if scan_type == ScanType.SUBDOMAINS:
            data = subdomain_scan.enumerate_subdomains(domain)
            previous = _previous_successful_scan(db, domain, scan_type)
            previous_hosts = previous.data["subdomains"] if previous and previous.data else None
            diff = subdomain_scan.diff_subdomains(previous_hosts, data["subdomains"])
            data["diff"] = diff
            if previous is not None:
                findings = _raise_findings_for_subdomains(db, domain, scan_result, diff)

        elif scan_type == ScanType.PORTS:
            data = port_scan.scan_ports(domain)
            previous = _previous_successful_scan(db, domain, scan_type)
            previous_ports = previous.data["open_ports"] if previous and previous.data else None
            diff = port_scan.diff_ports(previous_ports, data["open_ports"])
            data["diff"] = diff
            if previous is not None:
                findings = _raise_findings_for_ports(db, domain, scan_result, diff)

        elif scan_type == ScanType.TLS:
            data = tls_check.check_certificate(domain)
            findings = _raise_finding_for_tls(db, domain, scan_result, data)

        else:
            raise ValueError(f"Unsupported scan_type for run_scan: {scan_type}")

        scan_result.status = ScanStatus.SUCCESS
        scan_result.data = data

    except Exception as exc:  # noqa: BLE001 - persisted for operator visibility, not swallowed
        logger.exception("Scan %s failed for domain %s", scan_type, domain.name)
        scan_result.status = ScanStatus.FAILED
        scan_result.error = str(exc)

    scan_result.finished_at = datetime.now(timezone.utc)
    domain.last_scanned_at = scan_result.finished_at
    db.add(scan_result)
    db.add(domain)
    db.commit()
    db.refresh(scan_result)

    if findings and owner_email:
        for finding in findings:
            try:
                notify_finding(finding, owner_email)
                finding.notified_at = datetime.now(timezone.utc)
                db.add(finding)
            except Exception:
                logger.exception("Failed to notify finding %s", finding.id)
        db.commit()

    return scan_result
