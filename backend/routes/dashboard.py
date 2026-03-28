from fastapi import APIRouter, Query

from db.scan_logger import get_recent_scans, get_risk_totals
from models.contracts import DashboardSummaryResponse, ScanRecord

# Read-only analytics endpoints for dashboard widgets.
router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def dashboard_summary() -> DashboardSummaryResponse:
    # Aggregate counters for top-level cards.
    return get_risk_totals()


@router.get("/recent")
def dashboard_recent(limit: int = Query(default=25, ge=1, le=100)) -> list[ScanRecord]:
    # Paginated recent scan activity for tables/timelines.
    return get_recent_scans(limit=limit)
