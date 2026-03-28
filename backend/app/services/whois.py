"""WHOIS service interface."""

from app.services.base import ServiceStub


class WhoisService(ServiceStub):
    """Retrieve WHOIS and domain registration metadata."""

    async def lookup_domain(self, domain: str) -> dict:
        """Return WHOIS data for a domain."""

        await self.not_implemented(f"WHOIS lookup for {domain}")
