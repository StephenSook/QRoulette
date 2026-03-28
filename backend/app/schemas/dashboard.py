"""Schemas for dashboard endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.schemas.common import SchemaModel
from app.schemas.enums import Verdict
from app.schemas.protected_links import ProtectedLinkRecord
from app.schemas.repository import AlertSeverity, AlertStatus, RecentScanRecord
from models.contracts import RiskLevel


class DashboardOverviewRequest(SchemaModel):
    """Query params for `GET /api/dashboard/overview`."""

    days: int = Field(default=7, ge=1, le=90)


class DashboardRecentActivityMetrics(SchemaModel):
    """Recent activity counts for quick dashboard trend cards."""

    last_24h_total: int = 0
    last_24h_safe: int = 0
    last_24h_suspicious: int = 0
    last_24h_dangerous: int = 0


class DashboardOverviewMetrics(SchemaModel):
    """Aggregated dashboard counters."""

    total_scans: int = 0
    safe_count: int = 0
    suspicious_count: int = 0
    dangerous_count: int = 0
    unknown_count: int = 0
    latest_verdict: Verdict = Verdict.UNKNOWN
    recent_activity: DashboardRecentActivityMetrics = Field(
        default_factory=DashboardRecentActivityMetrics
    )


class DashboardOverviewResponse(SchemaModel):
    """Response payload for `GET /api/dashboard/overview`."""

    period_days: int
    metrics: DashboardOverviewMetrics
    message: str = "TODO: implement dashboard aggregation workflow."


class DashboardScansQuery(SchemaModel):
    """Query params for `GET /api/dashboard/scans`."""

    verdict: RiskLevel | None = None
    domain: str | None = Field(default=None, min_length=1)
    start_date: datetime | None = None
    end_date: datetime | None = None
    limit: int = Field(default=25, ge=1, le=200)


class DashboardScansResponse(SchemaModel):
    """Frontend-friendly scan list payload."""

    items: list[RecentScanRecord] = Field(default_factory=list)
    total: int = 0


class DashboardLinksQuery(SchemaModel):
    """Query params for `GET /api/dashboard/links`."""

    organization_id: str | None = None
    is_active: bool | None = None
    limit: int = Field(default=25, ge=1, le=200)


class DashboardLinkItem(ProtectedLinkRecord):
    """Protected-link item enriched with scan counts."""

    scan_count: int = 0
    dangerous_scan_count: int = 0
    suspicious_scan_count: int = 0
    last_scanned_at: datetime | None = None


class DashboardLinksResponse(SchemaModel):
    """Frontend-friendly protected-links payload."""

    items: list[DashboardLinkItem] = Field(default_factory=list)
    total: int = 0


class DashboardAlertsQuery(SchemaModel):
    """Query params for `GET /api/dashboard/alerts`."""

    organization_id: str | None = None
    status: AlertStatus | None = None
    limit: int = Field(default=25, ge=1, le=200)


class DashboardAlertItem(SchemaModel):
    """Unified persisted or derived dashboard alert."""

    id: str
    created_at: datetime
    source: Literal["persisted", "derived"]
    alert_type: str
    severity: AlertSeverity
    status: AlertStatus = "open"
    title: str
    message: str
    count: int = Field(default=1, ge=1)
    protected_link_id: str | None = None
    protected_link_label: str | None = None
    registrable_domain: str | None = None
    metadata: dict[str, object] = Field(default_factory=dict)


class DashboardAlertsResponse(SchemaModel):
    """Frontend-friendly alerts payload."""

    items: list[DashboardAlertItem] = Field(default_factory=list)
    total: int = 0
