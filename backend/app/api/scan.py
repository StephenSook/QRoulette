"""Scan routes."""

from fastapi import APIRouter, Depends, status

from app.api.deps import get_url_analysis_service
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.url_analysis import URLAnalysisService

router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("/url", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def scan_url(
    payload: ScanRequest,
    service: URLAnalysisService = Depends(get_url_analysis_service),
) -> ScanResponse:
    """Queue a URL scan once analysis orchestration is implemented."""

    _ = service
    return ScanResponse(
        message=f"TODO: implement URL scan workflow for {payload.url}",
    )
