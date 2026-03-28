"""Health endpoint schemas."""

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Healthcheck payload."""

    status: str
    service: str
    environment: str
    version: str
