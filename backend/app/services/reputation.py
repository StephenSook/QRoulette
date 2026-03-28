"""Domain reputation service interface."""

from app.services.base import ServiceStub


class ReputationService(ServiceStub):
    """Evaluate URL and domain reputation signals."""

    async def score_url(self, url: str) -> dict:
        """Return a reputation score payload for a URL."""

        await self.not_implemented(f"reputation scoring for {url}")
