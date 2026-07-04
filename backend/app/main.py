from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import settings

app = FastAPI(
    title="Atlas Lens API",
    version="0.1.0",
    description="Mission exposure intelligence and decision support API",
    docs_url="/docs" if settings.atlas_docs_enabled else None,
    redoc_url="/redoc" if settings.atlas_docs_enabled else None,
    openapi_url="/openapi.json" if settings.atlas_docs_enabled else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


@app.get("/")
def root():
    payload = {"product": "Atlas Lens", "api": "/api/health"}
    if settings.atlas_docs_enabled:
        payload["docs"] = "/docs"
    return payload
