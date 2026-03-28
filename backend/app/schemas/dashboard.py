"""Schemas for dashboard endpoints."""

from pydantic import BaseModel


class DashboardSummaryResponse(BaseModel):
    """Placeholder dashboard summary response."""

    status: str = "not_implemented"
    message: str
