"""Schemas for QR endpoints."""

from pydantic import Field

from app.schemas.common import SchemaModel, WebUrl


class QRCreateRequest(SchemaModel):
    """Request payload for `POST /api/qr/create`."""

    url: WebUrl
    size: int = Field(default=256, ge=128, le=2048)


class QRCreateResponse(SchemaModel):
    """Response payload for `POST /api/qr/create`."""

    url: WebUrl
    size: int
    status: str = "accepted"
    message: str = "TODO: implement QR creation workflow."
