"""Schemas for normalized TLS/SSL inspection results."""

from datetime import datetime

from pydantic import Field

from app.schemas.enums import SourceType, Verdict
from app.schemas.service_result import ExternalServiceResult


class SSLInfoResult(ExternalServiceResult):
    """Normalized certificate metadata for a host."""

    source_type: SourceType = SourceType.SSL_INFO
    host: str
    provider: str | None = None
    has_tls: bool = False
    issuer: str | None = None
    subject: str | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    days_until_expiry: int | None = None
    san_count: int | None = Field(default=None, ge=0)
    is_expired: bool | None = None
    self_signed: bool | None = None
    verdict: Verdict = Verdict.UNKNOWN
    reasons: list[str] = Field(default_factory=list)
