"""Schemas for redirect analysis endpoints."""

from pydantic import BaseModel, HttpUrl


class RedirectRequest(BaseModel):
    """Request payload for redirect inspection."""

    url: HttpUrl


class RedirectResponse(BaseModel):
    """Placeholder response for redirect inspection."""

    status: str = "accepted"
    message: str
