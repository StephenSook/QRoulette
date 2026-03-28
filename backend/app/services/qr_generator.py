"""QR generation service interface."""

from app.services.base import ServiceStub


class QRGeneratorService(ServiceStub):
    """Generate QR codes for URLs or stored scan results."""

    async def generate(self, url: str, size: int) -> dict:
        """Return QR generation metadata for a URL."""

        await self.not_implemented(f"QR generation for {url} at size {size}")
