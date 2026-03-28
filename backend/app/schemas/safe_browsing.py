"""Schemas for Google Safe Browsing service results."""

from typing import Any

from app.schemas.common import SchemaModel


class SafeBrowsingResult(SchemaModel):
    """Normalized result for a Safe Browsing URL lookup."""

    matched: bool
    threat_types: list[str]
    raw_response: dict[str, Any]
