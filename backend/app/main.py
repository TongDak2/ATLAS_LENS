from __future__ import annotations

import uuid

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse

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
    TrustedHostMiddleware,
    allowed_hosts=settings.allowed_hosts,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Atlas-API-Key", "X-Request-ID"],
)

app.include_router(router, prefix="/api")


@app.middleware("http")
async def security_headers_and_body_limit(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            body_size = int(content_length)
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
        if body_size > settings.atlas_max_request_body_bytes:
            return JSONResponse(status_code=413, content={"detail": "Request body too large"})

    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    if settings.atlas_env.lower() == "production":
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return response


@app.get("/")
def root():
    payload = {"product": "Atlas Lens", "api": "/api/health"}
    if settings.atlas_docs_enabled:
        payload["docs"] = "/docs"
    return payload
