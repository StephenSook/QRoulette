"""Supabase repository interface."""

from app.services.base import ServiceStub


class SupabaseRepository(ServiceStub):
    """Persist and retrieve application records from Supabase."""

    async def fetch_dashboard_summary(self) -> dict:
        """Return dashboard data from persistence."""

        await self.not_implemented("dashboard summary persistence")
