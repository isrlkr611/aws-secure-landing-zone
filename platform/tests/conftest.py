import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models import Domain, User
from app.security import generate_api_key, hash_api_key
from app.services.verification import mark_verified


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def user_with_key(db_session):
    raw_key = generate_api_key()
    user = User(email="owner@example.com", hashed_api_key=hash_api_key(raw_key))
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user, raw_key


@pytest.fixture()
def auth_headers(user_with_key):
    _, raw_key = user_with_key
    return {"X-API-Key": raw_key}


@pytest.fixture()
def unverified_domain(db_session, user_with_key):
    user, _ = user_with_key
    domain = Domain(name="example.com", owner_id=user.id)
    db_session.add(domain)
    db_session.commit()
    db_session.refresh(domain)
    return domain


@pytest.fixture()
def verified_domain(db_session, unverified_domain):
    mark_verified(unverified_domain)
    db_session.add(unverified_domain)
    db_session.commit()
    db_session.refresh(unverified_domain)
    return unverified_domain
