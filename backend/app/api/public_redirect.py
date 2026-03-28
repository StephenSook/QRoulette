"""Public redirect route for protected QR links."""

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse

from app.api.deps import get_protected_links_service
from app.schemas.common import error_response
from app.services.protected_links import ProtectedLinkNotFoundError, ProtectedLinksService

router = APIRouter(prefix="", tags=["public-redirect"])


@router.get("/go/{token}")
async def resolve_protected_redirect(
    token: str,
    request: Request,
    service: ProtectedLinksService = Depends(get_protected_links_service),
) -> Any:
    """Resolve a protected link token into a block payload or redirect."""

    try:
        outcome = await service.resolve_redirect(
            token=token,
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            country=request.headers.get("cf-ipcountry"),
        )
    except ProtectedLinkNotFoundError:
        payload = error_response(
            code="protected_link_not_found",
            message="Protected link token was not found.",
            details={"token": token},
        )
        return JSONResponse(status_code=404, content=payload.model_dump(mode="json"))

    if not outcome.decision.allowed:
        return JSONResponse(
            status_code=403,
            content=outcome.decision.model_dump(mode="json"),
        )

    return RedirectResponse(url=str(outcome.redirect_url), status_code=307)
