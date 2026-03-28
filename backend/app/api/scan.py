"""Scan routes."""

from fastapi import APIRouter, Depends, status

from app.api.deps import get_url_analysis_service
from app.schemas.common import ApiErrorResponse, ApiSuccessResponse, success_response
from app.schemas.scan import ScanAnalyzeRequest, ScanAnalyzeResponse
from app.services.url_analysis import URLAnalysisService

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
    service: URLAnalysisService = Depends(get_url_analysis_service),
) -> ApiSuccessResponse[ScanAnalyzeResponse]:
    """Run deterministic URL analysis for the submitted URL."""

    analysis = await service.analyze_url(str(payload.url))
    return success_response(
        ScanAnalyzeResponse(
            analysis=analysis,
            message=f"Analyzed URL domain signals for {payload.url}",
        )
    )
