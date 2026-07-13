import enum
import secrets
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def generate_verification_token() -> str:
    # 32 random hex chars - long enough that guessing it to fraudulently
    # "verify" a domain you don't own is not a practical attack.
    return secrets.token_hex(16)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_api_key: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    domains: Mapped[list["Domain"]] = relationship(back_populates="owner", cascade="all, delete-orphan")


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)

    # --- Legal safeguard state ---------------------------------------------
    # A domain is NOT scannable until verified_at is set. Every scan service
    # in app/services/ must check this before touching the network - see
    # services/verification.py and services/port_scan.py for the enforced
    # gate. This mirrors Google Search Console's DNS TXT ownership check.
    verification_token: Mapped[str] = mapped_column(String(64), default=generate_verification_token)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)

    owner: Mapped["User"] = relationship(back_populates="domains")
    scan_results: Mapped[list["ScanResult"]] = relationship(back_populates="domain", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="domain", cascade="all, delete-orphan")

    @property
    def is_verified(self) -> bool:
        return self.verified_at is not None

    @property
    def verification_dns_record(self) -> str:
        """Value the user must publish as a TXT record before any scan can run."""
        return f"platform-verification={self.verification_token}"


class ScanType(str, enum.Enum):
    SUBDOMAINS = "subdomains"
    PORTS = "ports"
    TLS = "tls"
    LEAKS = "leaks"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED_UNVERIFIED = "blocked_unverified"


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"))
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType))
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)
    data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    domain: Mapped["Domain"] = relationship(back_populates="scan_results")


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"))
    scan_result_id: Mapped[int | None] = mapped_column(ForeignKey("scan_results.id"), nullable=True)
    category: Mapped[str] = mapped_column(String(64))
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    description: Mapped[str] = mapped_column(Text)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    domain: Mapped["Domain"] = relationship(back_populates="findings")
