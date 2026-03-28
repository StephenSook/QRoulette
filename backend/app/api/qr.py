"""QR routes."""

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse

from app.api.deps import get_protected_links_service
from app.schemas.common import (
    ApiErrorResponse,
    ApiSuccessResponse,
    error_response,
    success_response,
)
from app.schemas.qr import QRCreateRequest, QRCreateResponse
from app.services.protected_links import InvalidProtectedLinkUrlError, ProtectedLinksService

router = APIRouter(prefix="/qr", tags=["qr"])


@router.post(
    "/create",
    response_model=ApiSuccessResponse[QRCreateResponse],
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ApiErrorResponse},
        500: {"model": ApiErrorResponse},
    },
)
async def create_qr_code(
    request: Request,
    payload: QRCreateRequest,
    service: ProtectedLinksService = Depends(get_protected_links_service),
) -> ApiSuccessResponse[QRCreateResponse]:
    """Create a tokenized protected QR link and return its payload."""

    try:
        result = await service.create_protected_link(
            original_url=payload.original_url,
            label=payload.label,
            organization_id=payload.organization_id,
            base_url=str(request.base_url).rstrip("/"),
        )
    except InvalidProtectedLinkUrlError as exc:
        payload = error_response(
            code="invalid_original_url",
            message=str(exc),
            details={"original_url": payload.original_url},
        )
        return JSONResponse(status_code=400, content=payload.model_dump(mode="json"))

    return success_response(result)
