"""Dashboard routes."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import get_supabase_repository
from app.schemas.common import ApiErrorResponse, ApiSuccessResponse, success_response
from app.schemas.dashboard import DashboardOverviewRequest, DashboardOverviewResponse
from app.services.supabase_repo import SupabaseRepository

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get(
    "/overview",
    response_model=ApiSuccessResponse[DashboardOverviewResponse],
    responses={
        400: {"model": ApiErrorResponse},
        500: {"model": ApiErrorResponse},
    },
)
async def get_dashboard_overview(
    params: Annotated[DashboardOverviewRequest, Depends()],
    repository: SupabaseRepository = Depends(get_supabase_repository),
) -> ApiSuccessResponse[DashboardOverviewResponse]:
    """Return aggregated dashboard overview metrics from Supabase."""

    return success_response(await repository.get_dashboard_overview(days=params.days))
