"""Redirect chain analysis service interface."""

from app.services.base import ServiceStub


class RedirectsService(ServiceStub):
    """Inspect redirect chains for destination URLs."""

    async def inspect_chain(self, url: str) -> dict:
        """Return redirect chain metadata for a URL."""

        await self.not_implemented(f"redirect chain inspection for {url}")
