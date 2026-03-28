"""Schemas for normalized WHOIS lookup results."""

from datetime import datetime

from pydantic import Field

from app.schemas.enums import SourceType
from app.schemas.service_result import ExternalServiceResult


class WhoisResult(ExternalServiceResult):
    """Normalized WHOIS metadata for a registrable domain."""

    source_type: SourceType = SourceType.WHOIS
    domain: str
    found: bool = False
    registrar: str | None = None
    registrant_name: str | None = None
    creation_date: datetime | None = None
    updated_date: datetime | None = None
    expiration_date: datetime | None = None
    domain_age_days: int | None = Field(default=None, ge=0)
    nameservers: list[str] = Field(default_factory=list)
    statuses: list[str] = Field(default_factory=list)
