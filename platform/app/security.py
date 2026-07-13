"""API key issuance and verification.

Deliberately hashed with SHA-256, not bcrypt: bcrypt is designed to make
low-entropy, human-chosen secrets (passwords) expensive to brute-force
offline. An API key here is 256 bits of `secrets.token_urlsafe` entropy -
brute-forcing it is infeasible regardless of hash speed, and a fast,
deterministic hash is what lets the auth dependency look a key up by
value (`WHERE hashed_api_key = ?`) instead of iterating every user and
running a slow compare against each one.
"""

from __future__ import annotations

import hashlib
import secrets

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def get_current_user(
    api_key: str | None = Security(_api_key_header),
    db: Session = Depends(get_db),
) -> User:
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header.",
        )

    user = db.query(User).filter(User.hashed_api_key == hash_api_key(api_key)).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )
    return user
