"""Shared service abstractions."""

from dataclasses import dataclass

import httpx

from app.core.config import Settings


@dataclass(slots=True)
class ServiceContext:
    """Shared runtime dependencies for service instances."""

    client: httpx.AsyncClient
    settings: Settings


class ServiceStub:
    """Base class for TODO service implementations."""

    def __init__(self, context: ServiceContext) -> None:
        self.context = context

    async def not_implemented(self, capability: str) -> None:
        """Raise a consistent placeholder error."""

        raise NotImplementedError(f"TODO: implement {capability}")
