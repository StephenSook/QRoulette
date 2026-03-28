"""Schemas for Gemini explanation results."""

from app.schemas.enums import SourceType
from app.schemas.service_result import ExternalServiceResult


class GeminiExplanationResult(ExternalServiceResult):
    """Normalized result for Gemini-generated scan explanations."""

    source_type: SourceType = SourceType.GEMINI
    model: str | None = None
    summary: str | None = None
