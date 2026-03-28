"""Gemini integration service interface."""

from app.services.base import ServiceStub


class GeminiService(ServiceStub):
    """Use Gemini for higher-level risk reasoning."""

    async def review_url(self, url: str) -> dict:
        """Return a Gemini-assisted verdict for a URL."""

        await self.not_implemented(f"Gemini review for {url}")
