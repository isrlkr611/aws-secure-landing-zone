from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models import ScanStatus, ScanType, Severity


class UserCreate(BaseModel):
    email: EmailStr


class UserCreated(BaseModel):
    email: EmailStr
    api_key: str = Field(description="Shown once. Store it - it cannot be recovered, only rotated.")


class DomainCreate(BaseModel):
    name: str = Field(description="Domain you own, e.g. example.com", max_length=255)


class DomainOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    is_verified: bool
    verified_at: datetime | None
    created_at: datetime
    last_scanned_at: datetime | None


class DomainVerificationInstructions(BaseModel):
    domain: str
    dns_record_type: str = "TXT"
    dns_record_name: str
    dns_record_value: str
    instructions: str


class VerificationResult(BaseModel):
    verified: bool
    domain: str
    detail: str


class ScanResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_type: ScanType
    status: ScanStatus
    data: dict | None
    error: str | None
    started_at: datetime
    finished_at: datetime | None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    category: str
    severity: Severity
    description: str
    detected_at: datetime
    notified_at: datetime | None
