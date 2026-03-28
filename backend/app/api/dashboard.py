"""Dashboard routes."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import get_supabase_repository
from app.schemas.common import ApiErrorResponse, ApiSuccessResponse, success_response
from app.schemas.dashboard import (
    DashboardAlertsQuery,
    DashboardAlertsResponse,
    DashboardLinksQuery,
    DashboardLinksResponse,
    DashboardOverviewRequest,
    DashboardOverviewResponse,
    DashboardScansQuery,
    DashboardScansResponse,
)
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


@router.get(
    "/scans",
    response_model=ApiSuccessResponse[DashboardScansResponse],
    responses={
        400: {"model": ApiErrorResponse},
        500: {"model": ApiErrorResponse},
    },
)
async def get_dashboard_scans(
    params: Annotated[DashboardScansQuery, Depends()],
    repository: SupabaseRepository = Depends(get_supabase_repository),
) -> ApiSuccessResponse[DashboardScansResponse]:
    """Return filtered recent scan activity for the dashboard."""

    items = await repository.list_recent_scans(params)
    return success_response(DashboardScansResponse(items=items, total=len(items)))


@router.get(
    "/links",
    response_model=ApiSuccessResponse[DashboardLinksResponse],
    responses={
        400: {"model": ApiErrorResponse},
        500: {"model": ApiErrorResponse},
    },
)
async def get_dashboard_links(
    params: Annotated[DashboardLinksQuery, Depends()],
    repository: SupabaseRepository = Depends(get_supabase_repository),
) -> ApiSuccessResponse[DashboardLinksResponse]:
    """Return protected links with dashboard scan rollups."""

    items = await repository.list_protected_links(params)
    return success_response(DashboardLinksResponse(items=items, total=len(items)))


@router.get(
    "/alerts",
    response_model=ApiSuccessResponse[DashboardAlertsResponse],
    responses={
        400: {"model": ApiErrorResponse},
        500: {"model": ApiErrorResponse},
    },
)
async def get_dashboard_alerts(
    params: Annotated[DashboardAlertsQuery, Depends()],
    repository: SupabaseRepository = Depends(get_supabase_repository),
) -> ApiSuccessResponse[DashboardAlertsResponse]:
    """Return persisted and derived dashboard alerts."""

    items = await repository.list_alerts(params)
    return success_response(DashboardAlertsResponse(items=items, total=len(items)))
