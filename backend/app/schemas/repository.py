"""Typed persistence models used by the Supabase repository layer."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.common import SchemaModel, WebUrl
from models.contracts import RiskLevel, ScanRecord

AlertSeverity = Literal["info", "warning", "critical"]
AlertStatus = Literal["open", "resolved", "muted"]


class OrganizationRecord(SchemaModel):
    """Organization row returned from Supabase."""

    id: str
    name: str
    slug: str | None = None
    created_at: datetime | None = None


class CreateProtectedLinkInput(SchemaModel):
    """Input payload for inserting a protected link."""

    token: str
    original_url: str
    normalized_url: WebUrl
    label: str
    organization_id: str | None = None
    is_active: bool = True


class ScanEventRecord(SchemaModel):
    """Raw scan event row."""

    id: str
    created_at: datetime | None = None
    organization_id: str | None = None
    protected_link_id: str | None = None
    qr_code_id: str | None = None
    protected_link_token: str | None = None
    protected_link_label: str | None = None
    scanned_url: str
    normalized_url: WebUrl | None = None
    registrable_domain: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    country: str | None = None


class CreateScanEventInput(SchemaModel):
    """Input payload for inserting a scan event."""

    organization_id: str | None = None
    protected_link_id: str | None = None
    qr_code_id: str | None = None
    protected_link_token: str | None = None
    protected_link_label: str | None = None
    scanned_url: str
    normalized_url: WebUrl | None = None
    registrable_domain: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    country: str | None = None


class ScanAnalysisRecord(SchemaModel):
    """Normalized analysis row linked to a scan event."""

    id: str
    created_at: datetime | None = None
    scan_event_id: str | None = None
    organization_id: str | None = None
    protected_link_id: str | None = None
    qr_code_id: str | None = None
    registrable_domain: str | None = None
    risk_score: int | None = None
    risk_level: RiskLevel | None = None
    flagged_safe_browsing: bool = False
    flagged_threat_intel: bool = False
    typosquatting_detected: bool = False
    domain_age_days: int | None = None
    redirect_hops: int | None = None
    ssl_valid: bool | None = None
    ai_summary: str | None = None
    analysis_payload: dict[str, Any] = Field(default_factory=dict)


class CreateScanAnalysisInput(SchemaModel):
    """Input payload for inserting a scan analysis."""

    scan_event_id: str | None = None
    organization_id: str | None = None
    protected_link_id: str | None = None
    qr_code_id: str | None = None
    registrable_domain: str | None = None
    risk_score: int | None = None
    risk_level: RiskLevel | None = None
    flagged_safe_browsing: bool = False
    flagged_threat_intel: bool = False
    typosquatting_detected: bool = False
    domain_age_days: int | None = None
    redirect_hops: int | None = None
    ssl_valid: bool | None = None
    ai_summary: str | None = None
    analysis_payload: dict[str, Any] = Field(default_factory=dict)


class AlertRecord(SchemaModel):
    """Alert row returned from Supabase."""

    id: str
    created_at: datetime | None = None
    organization_id: str | None = None
    protected_link_id: str | None = None
    scan_event_id: str | None = None
    scan_analysis_id: str | None = None
    severity: AlertSeverity = "warning"
    status: AlertStatus = "open"
    title: str
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProtectedLinksListParams(SchemaModel):
    """Query options for listing protected links."""

    organization_id: str | None = None
    is_active: bool | None = None
    limit: int = Field(default=25, ge=1, le=200)


class AlertsListParams(SchemaModel):
    """Query options for listing alerts."""

    organization_id: str | None = None
    status: AlertStatus | None = None
    limit: int = Field(default=25, ge=1, le=200)


class RecentScansQuery(SchemaModel):
    """Query options for recent scans."""

    limit: int = Field(default=25, ge=1, le=200)


class RecentScanRecord(ScanRecord):
    """Dashboard-oriented scan item enriched with protected-link context."""

    protected_link_id: str | None = None
    protected_link_token: str | None = None
    protected_link_label: str | None = None
