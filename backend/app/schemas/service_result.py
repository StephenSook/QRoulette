"""Shared result schema helpers for external service adapters."""

from typing import Any

from pydantic import Field

from app.schemas.common import SchemaModel
from app.schemas.enums import SourceType


class ExternalServiceResult(SchemaModel):
    """Common fields returned by all external service adapters."""

    source_type: SourceType
    available: bool = True
    error: str | None = None
    raw_response: dict[str, Any] = Field(default_factory=dict)
