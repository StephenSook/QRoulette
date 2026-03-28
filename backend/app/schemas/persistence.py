"""Schemas for best-effort scan persistence results."""

from typing import Any

from pydantic import Field

from app.schemas.common import SchemaModel


class PersistenceResult(SchemaModel):
    """Outcome of saving scan data to persistence."""

    available: bool = True
    persisted: bool = False
    record_id: str | None = None
    error: str | None = None
    raw_response: dict[str, Any] = Field(default_factory=dict)
