"""QR routes."""

from fastapi import APIRouter, Depends, status

from app.api.deps import get_qr_generator_service
from app.schemas.common import ApiErrorResponse, ApiSuccessResponse, success_response
from app.schemas.qr import QRCreateRequest, QRCreateResponse
from app.services.qr_generator import QRGeneratorService

router = APIRouter(prefix="/qr", tags=["qr"])


@router.post(
    "/create",
    response_model=ApiSuccessResponse[QRCreateResponse],
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"model": ApiErrorResponse},
        500: {"model": ApiErrorResponse},
    },
)
async def create_qr_code(
    payload: QRCreateRequest,
    service: QRGeneratorService = Depends(get_qr_generator_service),
) -> ApiSuccessResponse[QRCreateResponse]:
    """Accept a QR generation request without executing business logic yet."""

    _ = service
    return success_response(
        QRCreateResponse(
            url=payload.url,
            size=payload.size,
            message=f"TODO: implement QR generation for {payload.url}",
        )
    )
