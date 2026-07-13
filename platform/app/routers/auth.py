from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import UserCreate, UserCreated
from app.security import generate_api_key, hash_api_key

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserCreated, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)) -> UserCreated:
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered.")

    raw_key = generate_api_key()
    user = User(email=payload.email, hashed_api_key=hash_api_key(raw_key))
    db.add(user)
    db.commit()
    db.refresh(user)

    return UserCreated(email=user.email, api_key=raw_key)
