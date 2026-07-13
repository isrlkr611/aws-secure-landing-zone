from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Domain, ScanType, User
from app.schemas import ScanResultOut
from app.security import get_current_user
from app.services.scan_runner import run_scan

router = APIRouter(prefix="/domains/{domain_id}/scan", tags=["scans"])


def _get_owned_domain(domain_id: int, user: User, db: Session) -> Domain:
    domain = db.query(Domain).filter(Domain.id == domain_id, Domain.owner_id == user.id).first()
    if domain is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found.")
    return domain


@router.post("/{scan_type}", response_model=ScanResultOut, status_code=status.HTTP_201_CREATED)
def trigger_scan(
    domain_id: int,
    scan_type: ScanType,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanResultOut:
    """Run a scan synchronously and return the result.

    Synchronous-and-blocking is a deliberate MVP simplification (see
    platform/README.md "What's simplified for the MVP") - a production
    deployment runs this via the Kubernetes CronJob in platform/k8s/ instead
    of inline on the request path, so a slow nmap run doesn't hold an HTTP
    connection open.
    """
    domain = _get_owned_domain(domain_id, user, db)

    if scan_type not in (ScanType.SUBDOMAINS, ScanType.PORTS, ScanType.TLS):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{scan_type.value} scans are triggered separately (see /leaks endpoints).",
        )

    return run_scan(db, domain, scan_type, owner_email=user.email)
