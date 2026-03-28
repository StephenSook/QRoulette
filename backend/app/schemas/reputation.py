"""Schemas for normalized reputation service results."""

from pydantic import Field

from app.schemas.enums import SourceType, Verdict
from app.schemas.service_result import ExternalServiceResult


class ReputationResult(ExternalServiceResult):
    """Normalized reputation verdict and scoring details for a URL."""

    source_type: SourceType = SourceType.REPUTATION
    url: str
    provider: str | None = None
    score: float | None = Field(default=None, ge=0, le=100)
    verdict: Verdict = Verdict.UNKNOWN
    confidence: float | None = Field(default=None, ge=0, le=1)
    categories: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
