"""Redirect analysis routes."""

from fastapi import APIRouter, Depends, status

from app.api.deps import get_redirects_service
from app.schemas.redirect import RedirectRequest, RedirectResponse
from app.services.redirects import RedirectsService

router = APIRouter(prefix="/redirect", tags=["redirect"])


@router.post("/inspect", response_model=RedirectResponse, status_code=status.HTTP_202_ACCEPTED)
async def inspect_redirects(
    payload: RedirectRequest,
    service: RedirectsService = Depends(get_redirects_service),
) -> RedirectResponse:
    """Accept a redirect inspection request without running analysis yet."""

    _ = service
    return RedirectResponse(
        message=f"TODO: implement redirect chain inspection for {payload.url}",
    )
