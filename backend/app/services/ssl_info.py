"""SSL certificate inspection service interface."""

from app.services.base import ServiceStub


class SSLInfoService(ServiceStub):
    """Inspect TLS certificate details for remote hosts."""

    async def inspect_host(self, host: str) -> dict:
        """Return SSL metadata for a host."""

        await self.not_implemented(f"SSL inspection for {host}")
