"""Unit tests for the Google Safe Browsing v5 service."""

from __future__ import annotations

import pytest
import httpx

from app.core.config import Settings
from app.services.base import ServiceContext
from app.services.safe_browsing import SafeBrowsingService


def build_service(handler) -> SafeBrowsingService:
    """Create a Safe Browsing service backed by a mock transport."""

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    settings = Settings(
        GOOGLE_SAFE_BROWSING_API_KEY="test-api-key",
        SAFE_BROWSING_BASE_URL="https://safebrowsing.googleapis.com",
        SAFE_BROWSING_TIMEOUT_SECONDS=5,
    )
    return SafeBrowsingService(ServiceContext(client=client, settings=settings))


@pytest.mark.anyio
async def test_check_url_returns_clean_result() -> None:
    """A 200 response with empty threats should be treated as no match."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith(
            "https://safebrowsing.googleapis.com/v5/urls:search"
        )
        assert request.url.params["key"] == "test-api-key"
        assert request.url.params["urls[]"] == "https://example.com"
        return httpx.Response(200, json={"threats": [], "cacheDuration": "300s"})

    service = build_service(handler)

    try:
        result = await service.check_url("https://example.com")
    finally:
        await service.context.client.aclose()

    assert result.matched is False
    assert result.threat_types == []
    assert result.raw_response["cacheDuration"] == "300s"


@pytest.mark.anyio
async def test_check_url_returns_threat_match() -> None:
    """Threat responses should normalize matched threat types."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "threats": [
                    {
                        "url": "https://bad.example/download",
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    }
                ]
            },
        )

    service = build_service(handler)

    try:
        result = await service.check_url("https://bad.example/download")
    finally:
        await service.context.client.aclose()

    assert result.matched is True
    assert result.threat_types == ["MALWARE", "SOCIAL_ENGINEERING"]


@pytest.mark.anyio
async def test_check_url_raises_on_http_error() -> None:
    """Non-2xx responses should raise a predictable runtime error."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": {"message": "forbidden"}})

    service = build_service(handler)

    try:
        with pytest.raises(
            RuntimeError,
            match="Safe Browsing request failed with status 403.",
        ):
            await service.check_url("https://forbidden.example")
    finally:
        await service.context.client.aclose()
