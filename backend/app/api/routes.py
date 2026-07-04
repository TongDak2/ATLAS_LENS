from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.connectors.stealthmole import StealthMoleClient
from app.core.auth import AuthContext, enforce_rate_limit, require_api_key
from app.models import InvestigationRequest
from app.services.entity_extractor import has_investigable_target
from app.services.investigator import Investigator

router = APIRouter()
investigator = Investigator()


@router.get("/health")
def health():
    return {
        "ok": True,
        "product": "Atlas Lens",
        "live_mode_default": True,
    }


@router.get("/quotas")
def quotas(request: Request, auth: AuthContext = Depends(require_api_key)):
    enforce_rate_limit(auth, request, live=False)
    client = StealthMoleClient()
    if not client.configured:
        return {"configured": False, "detail": "StealthMole credentials not configured"}
    return client.get("/user/quotas")


@router.post("/investigate")
def investigate(req: InvestigationRequest, request: Request, auth: AuthContext = Depends(require_api_key)):
    enforce_rate_limit(auth, request, live=req.live)
    if not has_investigable_target(req.query):
        raise HTTPException(
            status_code=422,
            detail="A concrete investigation target is required. Include a real domain, URL, email address, or IP address.",
        )
    return investigator.investigate(req)
