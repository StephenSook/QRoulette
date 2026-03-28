"""Schemas for normalized redirect chain inspection results."""

from typing import Literal

from pydantic import Field

from app.schemas.common import SchemaModel
from app.schemas.enums import SourceType
from app.schemas.service_result import ExternalServiceResult

RedirectClassification = Literal["normal", "suspicious", "high_risk"]


class RedirectHop(SchemaModel):
    """One HTTP response hop in a redirect chain."""

    url: str
    status_code: int = Field(ge=100, le=599)
    location: str | None = None
    next_url: str | None = None
    hostname: str | None = None
    is_cross_domain: bool = False


class RedirectsResult(ExternalServiceResult):
    """Normalized redirect chain analysis for a URL."""

    source_type: SourceType = SourceType.REDIRECTS
    input_url: str
    final_url: str
    hop_count: int = Field(default=0, ge=0)
    classification: RedirectClassification = "normal"
    has_cross_domain_redirect: bool = False
    hops: list[RedirectHop] = Field(default_factory=list)
