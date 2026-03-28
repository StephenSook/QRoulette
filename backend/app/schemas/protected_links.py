"""Schemas for protected QR links and public redirect decisions."""

from datetime import datetime

from pydantic import Field

from app.schemas.common import SchemaModel, WebUrl
from models.contracts import ScanDecisionResponse


class QRArtifact(SchemaModel):
    """QR artifact metadata for a protected link."""

    format: str = "payload"
    payload_value: str
    png_bytes_base64: str | None = None
    svg_markup: str | None = None


class ProtectedLinkRecord(SchemaModel):
    """Persisted protected-link record resolved from a token."""

    id: str
    token: str
    original_url: str
    normalized_url: WebUrl
    label: str
    organization_id: str | None = None
    is_active: bool = True
    created_at: datetime | None = None


class ProtectedRedirectOutcome(SchemaModel):
    """Reusable allow/block decision produced for a protected link token."""

    protected_link: ProtectedLinkRecord
    decision: ScanDecisionResponse
    redirect_url: WebUrl | None = None


class QRCreateRequest(SchemaModel):
    """Request payload for `POST /api/qr/create`."""

    original_url: str = Field(min_length=1)
    label: str = Field(min_length=1, max_length=255)
    organization_id: str | None = Field(default=None, max_length=255)


class QRCreateResponse(SchemaModel):
    """Response payload for `POST /api/qr/create`."""

    token: str
    protected_url: WebUrl
    qr_payload_value: str
    normalized_url: WebUrl
    label: str
    organization_id: str | None = None
    artifact: QRArtifact
