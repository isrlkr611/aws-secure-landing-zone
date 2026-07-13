import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.database import Base, engine
from app.routers import auth, domains, leaks, scans

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(_: FastAPI):
    # MVP uses create_all for local dev / demo simplicity. A production
    # deployment manages schema migrations with Alembic instead - see
    # platform/README.md "What's simplified for the MVP".
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Attack Surface Monitor",
    description=(
        "Continuous external attack surface monitoring: subdomains, open "
        "ports, TLS certificate expiry, and leaked credentials - gated by "
        "mandatory DNS TXT domain ownership verification."
    ),
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/healthz", tags=["meta"])
def healthz() -> dict:
    return {"status": "ok"}


app.include_router(auth.router)
app.include_router(domains.router)
app.include_router(scans.router)
app.include_router(leaks.router)
