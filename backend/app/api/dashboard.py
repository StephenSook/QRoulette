"""Dashboard routes."""

from fastapi import APIRouter, Depends

from app.api.deps import get_supabase_repository
from app.schemas.dashboard import DashboardSummaryResponse
from app.services.supabase_repo import SupabaseRepository

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary(
    repository: SupabaseRepository = Depends(get_supabase_repository),
) -> DashboardSummaryResponse:
    """Return a placeholder dashboard summary response."""

    _ = repository
    return DashboardSummaryResponse(
        message="TODO: implement dashboard aggregation from Supabase.",
    )
