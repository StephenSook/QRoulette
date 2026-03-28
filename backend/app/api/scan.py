"""Scan routes."""

from fastapi import APIRouter, Depends, status

from app.api.deps import get_scan_analysis_service
from app.schemas.common import ApiErrorResponse, ApiSuccessResponse, success_response
from app.schemas.scan import ScanAnalyzeRequest, ScanAnalyzeResponse
from app.services.scan_analysis import ScanAnalysisService

router = APIRouter(prefix="/scan", tags=["scan"])


@router.post(
    "/analyze",
    response_model=ApiSuccessResponse[ScanAnalyzeResponse],
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"model": ApiErrorResponse},
        500: {"model": ApiErrorResponse},
    },
)
async def analyze_url(
    payload: ScanAnalyzeRequest,
    service: ScanAnalysisService = Depends(get_scan_analysis_service),
) -> ApiSuccessResponse[ScanAnalyzeResponse]:
    """Run the main scan analysis workflow for the submitted URL."""

    return success_response(await service.analyze_scan(str(payload.url)))
