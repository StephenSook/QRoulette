"""Scan routes."""

from fastapi import APIRouter, Depends, status

from app.api.deps import get_url_analysis_service
from app.schemas.common import ApiErrorResponse, ApiSuccessResponse, success_response
from app.schemas.domain import (
    RedirectResult,
    RiskSignal,
    ScanVerdict,
    ScoreBreakdownItem,
    UrlAnalysisResult,
)
from app.schemas.enums import SourceType, Verdict
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
    """Queue a URL scan once analysis orchestration is implemented."""

    _ = service
    analysis = UrlAnalysisResult(
        input_url=payload.url,
        normalized_url=payload.url,
        redirect_result=RedirectResult(
            input_url=payload.url,
            final_url=payload.url,
            chain=[payload.url],
            hop_count=0,
            has_cross_domain_redirect=False,
        ),
        risk_signals=[
            RiskSignal(
                source_type=SourceType.URL_ANALYSIS,
                verdict=Verdict.UNKNOWN,
                signal="analysis_not_implemented",
                details="URL analysis orchestration is still a TODO stub.",
                confidence=0.0,
                metadata={"status": "stub"},
            )
        ],
        score_breakdown=[
            ScoreBreakdownItem(
                source_type=SourceType.URL_ANALYSIS,
                label="base_score",
                score=0,
                weight=1.0,
                rationale="Scoring pipeline has not been implemented yet.",
            )
        ],
        scan_verdict=ScanVerdict(
            verdict=Verdict.UNKNOWN,
            score=0,
            summary="Analysis pipeline is not implemented yet.",
            confidence=0.0,
        ),
    )
    return success_response(
        ScanAnalyzeResponse(
            analysis=analysis,
            message=f"TODO: implement URL scan workflow for {payload.url}",
        )
    )
