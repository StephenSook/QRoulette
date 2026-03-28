"""Shared HTTP client helpers."""

import httpx

from app.core.config import Settings


def build_async_client(settings: Settings) -> httpx.AsyncClient:
    """Create the shared async HTTP client used by service stubs."""

    timeout = httpx.Timeout(settings.http_timeout_seconds)
    headers = {"User-Agent": f"{settings.app_name}/{settings.app_version}"}

    return httpx.AsyncClient(
        timeout=timeout,
        headers=headers,
        follow_redirects=True,
    )
