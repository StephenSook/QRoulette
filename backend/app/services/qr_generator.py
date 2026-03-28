"""QR generation service for protected-link payloads."""

from app.schemas.protected_links import QRArtifact
from app.services.base import ServiceStub


class QRGeneratorService(ServiceStub):
    """Generate QR artifacts for protected links."""

    async def generate(self, protected_url: str) -> QRArtifact:
        """Return MVP QR metadata while binary generation is deferred."""

        return QRArtifact(
            format="payload",
            payload_value=protected_url,
        )
