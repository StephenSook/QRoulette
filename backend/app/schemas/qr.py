"""Schemas for QR endpoints."""

from pydantic import BaseModel, HttpUrl


class QRGenerateRequest(BaseModel):
    """Request payload for QR generation."""

    url: HttpUrl
    size: int = 256


class QRGenerateResponse(BaseModel):
    """Placeholder response for QR generation."""

    status: str = "accepted"
    message: str
