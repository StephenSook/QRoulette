"""Threat intelligence service interface."""

from app.services.base import ServiceStub


class ThreatIntelService(ServiceStub):
    """Aggregate third-party threat intelligence signals."""

    async def lookup_indicators(self, url: str) -> dict:
        """Return threat intelligence data for a URL."""

        await self.not_implemented(f"threat intel lookup for {url}")
