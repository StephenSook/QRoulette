"""QR routes."""

from fastapi import APIRouter, Depends, status

from app.api.deps import get_qr_generator_service
from app.schemas.qr import QRGenerateRequest, QRGenerateResponse
from app.services.qr_generator import QRGeneratorService

router = APIRouter(prefix="/qr", tags=["qr"])


@router.post("/generate", response_model=QRGenerateResponse, status_code=status.HTTP_202_ACCEPTED)
async def generate_qr_code(
    payload: QRGenerateRequest,
    service: QRGeneratorService = Depends(get_qr_generator_service),
) -> QRGenerateResponse:
    """Accept a QR generation request without executing business logic yet."""

    _ = service
    return QRGenerateResponse(
        message=f"TODO: implement QR generation for {payload.url}",
    )
