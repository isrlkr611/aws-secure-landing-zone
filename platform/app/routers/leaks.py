from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Domain, Finding, ScanResult, ScanStatus, ScanType, Severity, User
from app.schemas import ScanResultOut
from app.security import get_current_user
from app.services.alerting import notify_finding
from app.services.leak_check import HIBPNotConfigured, check_leaked_credentials
from app.services.verification import require_verified

router = APIRouter(prefix="/domains/{domain_id}/leaks", tags=["leaks"])


class LeakCheckRequest(BaseModel):
    emails: list[EmailStr]


def _get_owned_domain(domain_id: int, user: User, db: Session) -> Domain:
    domain = db.query(Domain).filter(Domain.id == domain_id, Domain.owner_id == user.id).first()
    if domain is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found.")
    return domain


@router.post("/check", response_model=ScanResultOut, status_code=status.HTTP_201_CREATED)
def check_leaks(
    domain_id: int,
    payload: LeakCheckRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanResultOut:
    domain = _get_owned_domain(domain_id, user, db)

    scan_result = ScanResult(domain_id=domain.id, scan_type=ScanType.LEAKS, status=ScanStatus.RUNNING)
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

    try:
        data = check_leaked_credentials(domain, [str(e) for e in payload.emails])
        scan_result.status = ScanStatus.SUCCESS
        scan_result.data = data
    except HIBPNotConfigured as exc:
        scan_result.status = ScanStatus.FAILED
        scan_result.error = str(exc)
        scan_result.finished_at = datetime.now(timezone.utc)
        db.add(scan_result)
        db.commit()
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        scan_result.status = ScanStatus.FAILED
        scan_result.error = str(exc)
        scan_result.finished_at = datetime.now(timezone.utc)
        db.add(scan_result)
        db.commit()
        raise

    scan_result.finished_at = datetime.now(timezone.utc)
    db.add(scan_result)
    db.commit()
    db.refresh(scan_result)

    if data["breached"]:
        finding = Finding(
            domain_id=domain.id,
            scan_result_id=scan_result.id,
            category="leaked_credentials",
            severity=Severity.CRITICAL,
            description=f"{len(data['breached'])} address(es) found in known breaches: "
            f"{', '.join(data['breached'].keys())}",
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)
        try:
            notify_finding(finding, user.email)
            finding.notified_at = datetime.now(timezone.utc)
            db.add(finding)
            db.commit()
        except Exception:
            pass

    return scan_result
