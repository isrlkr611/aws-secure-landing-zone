from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Domain, Finding, ScanResult, User
from app.schemas import (
    DomainCreate,
    DomainOut,
    DomainVerificationInstructions,
    FindingOut,
    ScanResultOut,
    VerificationResult,
)
from app.security import get_current_user
from app.services.verification import mark_verified, verify_domain_ownership

router = APIRouter(prefix="/domains", tags=["domains"])


def _get_owned_domain(domain_id: int, user: User, db: Session) -> Domain:
    domain = db.query(Domain).filter(Domain.id == domain_id, Domain.owner_id == user.id).first()
    if domain is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found.")
    return domain


@router.post("", response_model=DomainVerificationInstructions, status_code=status.HTTP_201_CREATED)
def add_domain(
    payload: DomainCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DomainVerificationInstructions:
    normalized = payload.name.strip().lower()

    existing = db.query(Domain).filter(Domain.name == normalized).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This domain is already registered by a user on this platform.",
        )

    domain = Domain(name=normalized, owner_id=user.id)
    db.add(domain)
    db.commit()
    db.refresh(domain)

    return DomainVerificationInstructions(
        domain=domain.name,
        dns_record_name=domain.name,
        dns_record_value=domain.verification_dns_record,
        instructions=(
            f"Add a TXT record at '{domain.name}' with the value "
            f"'{domain.verification_dns_record}', then call "
            f"POST /domains/{domain.id}/verify. Scanning is disabled until "
            f"ownership is verified."
        ),
    )


@router.get("", response_model=list[DomainOut])
def list_domains(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[Domain]:
    return db.query(Domain).filter(Domain.owner_id == user.id).all()


@router.get("/{domain_id}", response_model=DomainOut)
def get_domain(domain_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Domain:
    return _get_owned_domain(domain_id, user, db)


@router.post("/{domain_id}/verify", response_model=VerificationResult)
def verify_domain(
    domain_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> VerificationResult:
    domain = _get_owned_domain(domain_id, user, db)

    outcome = verify_domain_ownership(domain)
    if outcome.verified and not domain.is_verified:
        mark_verified(domain)
        db.add(domain)
        db.commit()

    return VerificationResult(verified=domain.is_verified, domain=domain.name, detail=outcome.detail)


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_domain(domain_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> None:
    domain = _get_owned_domain(domain_id, user, db)
    db.delete(domain)
    db.commit()


@router.get("/{domain_id}/scans", response_model=list[ScanResultOut])
def list_scans(
    domain_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[ScanResult]:
    domain = _get_owned_domain(domain_id, user, db)
    return (
        db.query(ScanResult)
        .filter(ScanResult.domain_id == domain.id)
        .order_by(ScanResult.started_at.desc())
        .all()
    )


@router.get("/{domain_id}/findings", response_model=list[FindingOut])
def list_findings(
    domain_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[Finding]:
    domain = _get_owned_domain(domain_id, user, db)
    return (
        db.query(Finding)
        .filter(Finding.domain_id == domain.id)
        .order_by(Finding.detected_at.desc())
        .all()
    )
