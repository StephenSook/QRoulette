"""Schemas for normalized threat intelligence results."""

from pydantic import Field

from app.schemas.enums import SourceType, Verdict
from app.schemas.service_result import ExternalServiceResult


class ThreatIntelResult(ExternalServiceResult):
    """Normalized threat-intel verdict for a URL or indicator."""

    source_type: SourceType = SourceType.THREAT_INTEL
    url: str
    provider: str | None = None
    matched: bool = False
    verdict: Verdict = Verdict.UNKNOWN
    confidence: float | None = Field(default=None, ge=0, le=1)
    indicator_count: int = Field(default=0, ge=0)
    indicators: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
