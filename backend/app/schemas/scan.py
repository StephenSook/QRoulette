"""Schemas for scan endpoints."""

from pydantic import BaseModel, HttpUrl


class ScanRequest(BaseModel):
    """Request payload for a URL scan."""

    url: HttpUrl


class ScanResponse(BaseModel):
    """Placeholder response for scan operations."""

    status: str = "queued"
    message: str
