"""Google Safe Browsing service interface."""

from app.services.base import ServiceStub


class SafeBrowsingService(ServiceStub):
    """Query Google Safe Browsing for malicious URL signals."""

    async def check_url(self, url: str) -> dict:
        """Return Safe Browsing verdict data for a URL."""

        await self.not_implemented(f"Safe Browsing lookup for {url}")
