"""Schemas for dashboard endpoints."""

from pydantic import Field

from app.schemas.common import SchemaModel
from app.schemas.enums import Verdict


class DashboardOverviewRequest(SchemaModel):
    """Query params for `GET /api/dashboard/overview`."""

    days: int = Field(default=7, ge=1, le=90)


class DashboardOverviewMetrics(SchemaModel):
    """Aggregated dashboard counters."""

    total_scans: int = 0
    safe_count: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0
    unknown_count: int = 0
    latest_verdict: Verdict = Verdict.UNKNOWN


class DashboardOverviewResponse(SchemaModel):
    """Response payload for `GET /api/dashboard/overview`."""

    period_days: int
    metrics: DashboardOverviewMetrics
    message: str = "TODO: implement dashboard aggregation workflow."
