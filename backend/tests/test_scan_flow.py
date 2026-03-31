"""Tests for the main scan analysis flow."""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient
import pytest

from app.api.deps import get_scan_analysis_service
from app.core.app import create_application
from app.core.config import Settings
from app.core.logging import get_logger
from app.core.scoring import ScoringInputs, calculate_risk_score
from app.schemas.redirects import RedirectsResult
from app.schemas.reputation import ReputationResult
from app.schemas.scan import ScanAnalyzeResponse
from app.schemas.ssl_info import SSLInfoResult
from app.schemas.threat_intel import ThreatIntelResult
from app.schemas.whois import WhoisResult
from app.schemas.enums import Verdict
from app.services.base import ServiceContext
from app.services.scan_analysis import ScanAnalysisService
from app.services.url_analysis import analyze_url_value


class _StaticUrlAnalysisService:
    async def analyze_url(self, url: str):
        return analyze_url_value(url)


class _FailingSafeBrowsingService:
    async def check_url(self, url: str):
        raise RuntimeError("safe browsing unavailable")


class _StaticWhoisService:
    async def lookup_domain(self, domain: str):
        return WhoisResult(
            domain=domain,
            available=True,
            found=True,
            domain_age_days=5,
        )


class _StaticReputationService:
    async def score_url(self, url: str):
        return ReputationResult(
            url=url,
            available=True,
            score=20,
            verdict=Verdict.MALICIOUS,
            reasons=["Reputation provider score is low."],
        )


class _StaticThreatIntelService:
    async def lookup_indicators(self, url: str):
        return ThreatIntelResult(
            url=url,
            available=True,
            matched=False,
        )


class _FailingSSLInfoService:
    async def inspect_host(self, host: str):
        raise RuntimeError("ssl provider unavailable")


class _StaticRedirectsService:
    async def inspect_chain(self, url: str):
        return RedirectsResult(
            input_url=url,
            final_url=url,
            available=True,
            hop_count=3,
            classification="suspicious",
        )


class _FailingGeminiService:
    async def review_url(self, **kwargs):
        raise RuntimeError("gemini unavailable")


class _FailingSupabaseRepository:
    async def save_scan_result(self, payload):
        raise RuntimeError("supabase unavailable")


@pytest.mark.anyio
async def test_scan_analysis_service_tolerates_partial_failures() -> None:
    """Provider failures should not fail the whole scan workflow."""

    context = ServiceContext(client=httpx.AsyncClient(), settings=Settings())
    service = ScanAnalysisService(
        context,
        url_analysis_service=_StaticUrlAnalysisService(),
        safe_browsing_service=_FailingSafeBrowsingService(),
        whois_service=_StaticWhoisService(),
        reputation_service=_StaticReputationService(),
        threat_intel_service=_StaticThreatIntelService(),
        ssl_info_service=_FailingSSLInfoService(),
        redirects_service=_StaticRedirectsService(),
        gemini_service=_FailingGeminiService(),
        supabase_repository=_FailingSupabaseRepository(),
        logger=get_logger("qroulette.test.scan_analysis"),
    )

    try:
        result = await service.analyze_scan("https://example.com/login")
    finally:
        await context.client.aclose()

    assert result.scan_id
    assert result.analysis.registrable_domain == "example.com"
    assert result.risk.verdict == "dangerous"
    assert result.explanation == result.risk.summary
    assert result.persisted is False


def _build_route_response(url: str) -> ScanAnalyzeResponse:
    analysis = analyze_url_value(url)
    risk = calculate_risk_score(ScoringInputs(url_analysis=analysis))
    return ScanAnalyzeResponse(
        scan_id="scan-test-123",
        analysis=analysis,
        risk=risk,
        explanation=risk.summary,
        persisted=False,
        message="ok",
    )


def test_scan_route_delegates_to_orchestrator() -> None:
    """The route should stay thin and delegate to the orchestrator service."""

    app = create_application()
    calls = {"count": 0}

    class _FakeScanService:
        async def analyze_scan(self, url: str) -> ScanAnalyzeResponse:
            calls["count"] += 1
            return _build_route_response(url)

    app.dependency_overrides[get_scan_analysis_service] = lambda: _FakeScanService()

    with TestClient(app) as client:
        response = client.post(
            "/api/scan/analyze",
            json={"url": "https://example.com"},
        )

    app.dependency_overrides.clear()

    assert response.status_code == 202
    assert calls["count"] == 1
    body = response.json()
    assert body["data"]["scan_id"] == "scan-test-123"
    assert body["data"]["risk"]["verdict"] == "safe"


def test_scan_route_rejects_invalid_url() -> None:
    """Route validation should still fail early for invalid URLs."""

    app = create_application()

    class _FakeScanService:
        async def analyze_scan(self, url: str) -> ScanAnalyzeResponse:
            return _build_route_response(url)

    app.dependency_overrides[get_scan_analysis_service] = lambda: _FakeScanService()

    with TestClient(app) as client:
        response = client.post(
            "/api/scan/analyze",
            json={"url": "not-a-url"},
        )

    app.dependency_overrides.clear()

    assert response.status_code == 422
