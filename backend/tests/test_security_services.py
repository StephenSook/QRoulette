"""Unit tests for the async security service adapters."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.core.config import Settings
from app.services.base import ServiceContext
from app.services.redirects import RedirectsService
from app.services.reputation import ReputationService
from app.services.ssl_info import SSLInfoService
from app.services.threat_intel import ThreatIntelService
from app.services.whois import WhoisService


def build_context(handler=None, **settings_overrides) -> ServiceContext:
    """Create a shared service context for unit tests."""

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler) if handler else None,
        follow_redirects=True,
    )
    settings = Settings(**settings_overrides)
    return ServiceContext(client=client, settings=settings)


@pytest.mark.anyio
async def test_whois_lookup_computes_domain_age_days() -> None:
    """WHOIS responses should normalize the creation date into domain age."""

    created_at = datetime.now(tz=UTC) - timedelta(days=45)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["domainName"] == "example.com"
        return httpx.Response(
            200,
            json={
                "WhoisRecord": {
                    "domainName": "example.com",
                    "registrarName": "Example Registrar",
                    "createdDate": created_at.isoformat(),
                    "nameServers": {"hostNames": ["ns1.example.com", "ns2.example.com"]},
                }
            },
        )

    context = build_context(
        handler,
        WHOIS_XML_API_KEY="test-whois-key",
        WHOIS_BASE_URL="https://whois.example.test",
        WHOIS_TIMEOUT_SECONDS=5,
    )
    service = WhoisService(context)

    try:
        result = await service.lookup_domain("example.com")
    finally:
        await context.client.aclose()

    assert result.available is True
    assert result.found is True
    assert result.registrar == "Example Registrar"
    assert result.domain_age_days == 45
    assert result.nameservers == ["ns1.example.com", "ns2.example.com"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    (
        "redirect_targets",
        "expected_hops",
        "expected_classification",
        "expected_final_url",
    ),
    [
        ([], 0, "normal", "https://redirect.test/start"),
        (["/one", "/two", "/final"], 3, "suspicious", "https://redirect.test/final"),
        (
            ["/one", "/two", "/three", "/final"],
            4,
            "high_risk",
            "https://redirect.test/final",
        ),
    ],
)
async def test_redirects_service_captures_chain_and_classifies_risk(
    redirect_targets: list[str],
    expected_hops: int,
    expected_classification: str,
    expected_final_url: str,
) -> None:
    """Redirect inspection should preserve history and hop-based classification."""

    transitions: dict[str, str] = {}
    if redirect_targets:
        transitions["/start"] = redirect_targets[0]
        for current, nxt in zip(redirect_targets, redirect_targets[1:]):
            transitions[current] = nxt

    def handler(request: httpx.Request) -> httpx.Response:
        target = transitions.get(request.url.path)
        if target:
            return httpx.Response(
                302,
                headers={"location": f"https://redirect.test{target}"},
                request=request,
            )
        return httpx.Response(200, json={"ok": True}, request=request)

    context = build_context(handler, REDIRECTS_TIMEOUT_SECONDS=5)
    service = RedirectsService(context)

    try:
        result = await service.inspect_chain("https://redirect.test/start")
    finally:
        await context.client.aclose()

    assert result.available is True
    assert result.hop_count == expected_hops
    assert result.classification == expected_classification
    assert result.final_url == expected_final_url
    assert len(result.hops) == expected_hops


@pytest.mark.anyio
async def test_reputation_service_returns_fallback_when_unconfigured() -> None:
    """Missing reputation config should return a typed fallback instead of raising."""

    context = build_context(REPUTATION_BASE_URL="")
    service = ReputationService(context)

    try:
        result = await service.score_url("https://example.com")
    finally:
        await context.client.aclose()

    assert result.available is False
    assert result.error == "Reputation provider is not configured."
    assert result.score is None


@pytest.mark.anyio
async def test_threat_intel_service_normalizes_indicator_matches() -> None:
    """Threat-intel adapters should flatten indicators into a consistent result."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "provider": "intel.example",
                "matched": True,
                "verdict": "malicious",
                "confidence": 0.9,
                "indicators": [{"name": "phishing"}, {"indicator": "botnet"}],
                "reasons": ["Listed in partner feed"],
            },
            request=request,
        )

    context = build_context(
        handler,
        THREAT_INTEL_BASE_URL="https://intel.example/api/lookup",
        THREAT_INTEL_API_KEY="secret",
        THREAT_INTEL_TIMEOUT_SECONDS=5,
    )
    service = ThreatIntelService(context)

    try:
        result = await service.lookup_indicators("https://bad.example")
    finally:
        await context.client.aclose()

    assert result.available is True
    assert result.matched is True
    assert result.indicator_count == 2
    assert result.indicators == ["phishing", "botnet"]
    assert result.reasons == ["Listed in partner feed"]


@pytest.mark.anyio
async def test_ssl_info_service_normalizes_certificate_expiry() -> None:
    """SSL inspection should compute expiry metadata from provider dates."""

    expires_at = datetime.now(tz=UTC) + timedelta(days=10)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "provider": "ssl.example",
                "certificate": {
                    "issuer": "Example CA",
                    "subject": "www.example.com",
                    "notBefore": (expires_at - timedelta(days=30)).isoformat(),
                    "notAfter": expires_at.isoformat(),
                    "subjectAltNames": ["www.example.com", "example.com"],
                    "self_signed": False,
                },
            },
            request=request,
        )

    context = build_context(
        handler,
        SSL_INFO_BASE_URL="https://ssl.example/api/check",
        SSL_INFO_TIMEOUT_SECONDS=5,
    )
    service = SSLInfoService(context)

    try:
        result = await service.inspect_host("www.example.com")
    finally:
        await context.client.aclose()

    assert result.available is True
    assert result.has_tls is True
    assert result.is_expired is False
    assert result.days_until_expiry == 10
    assert result.san_count == 2
