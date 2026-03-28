"""URL analysis orchestration interface."""

from app.services.base import ServiceStub


class URLAnalysisService(ServiceStub):
    """Coordinate the URL analysis workflow across signal providers."""

    async def analyze_url(self, url: str) -> dict:
        """Return a consolidated URL analysis result."""

        await self.not_implemented(f"URL analysis workflow for {url}")
