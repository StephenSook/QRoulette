"""Schemas for scan endpoints."""

from app.schemas.common import SchemaModel, WebUrl
from app.schemas.domain import UrlAnalysisResult
from app.core.scoring import DeterministicScoreResult


class ScanAnalyzeRequest(SchemaModel):
    """Request payload for `POST /api/scan/analyze`."""

    url: WebUrl


class ScanAnalyzeResponse(SchemaModel):
    """Response payload for `POST /api/scan/analyze`."""

    scan_id: str
    analysis: UrlAnalysisResult
    risk: DeterministicScoreResult
    explanation: str | None = None
    persisted: bool = False
    message: str = "Scan analysis completed."
