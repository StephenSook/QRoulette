"""Schemas for scan endpoints."""

from app.schemas.common import SchemaModel, WebUrl
from app.schemas.domain import UrlAnalysisResult


class ScanAnalyzeRequest(SchemaModel):
    """Request payload for `POST /api/scan/analyze`."""

    url: WebUrl


class ScanAnalyzeResponse(SchemaModel):
    """Response payload for `POST /api/scan/analyze`."""

    analysis: UrlAnalysisResult
    message: str = "TODO: implement URL analysis workflow."
