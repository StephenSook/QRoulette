"""Tests for the business QR protected-link flow."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.deps import get_protected_links_service
from app.core.app import create_application
from app.schemas.protected_links import ProtectedLinkRecord, ProtectedRedirectOutcome
from app.services.protected_links import ProtectedLinkNotFoundError
from models.contracts import RiskAnalysis, ScanDecisionResponse


def _build_outcome(*, token: str, allowed: bool) -> ProtectedRedirectOutcome:
    destination = "https://example.com/final"
    risk_level = "safe" if allowed else "danger"
    return ProtectedRedirectOutcome(
        protected_link=ProtectedLinkRecord(
            id="plink_123",
            token=token,
            original_url="example.com/final",
            normalized_url=destination,
            label="Cafe table QR",
            organization_id="org_123",
            is_active=True,
        ),
        decision=ScanDecisionResponse(
            allowed=allowed,
            destination=destination,
            reason="Allowed by risk policy." if allowed else "Blocked by risk policy.",
            analysis=RiskAnalysis(
                risk_score=5 if allowed else 95,
                risk_level=risk_level,
                flagged_safe_browsing=not allowed,
                flagged_threat_intel=False,
                typosquatting_detected=False,
                domain_age_days=None,
                redirect_hops=0,
                ssl_valid=True,
                ai_summary="ok" if allowed else "blocked",
            ),
        ),
        redirect_url=destination if allowed else None,
    )


def test_go_route_redirects_for_safe_token() -> None:
    """Safe protected links should issue a redirect response."""

    app = create_application()

    class _FakeProtectedLinksService:
        async def resolve_redirect(self, **kwargs) -> ProtectedRedirectOutcome:
            assert kwargs["token"] == "safe-token"
            return _build_outcome(token="safe-token", allowed=True)

    app.dependency_overrides[get_protected_links_service] = lambda: _FakeProtectedLinksService()

    with TestClient(app) as client:
        response = client.get("/go/safe-token", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 307
    assert response.headers["location"] == "https://example.com/final"


def test_go_route_blocks_dangerous_token() -> None:
    """Dangerous protected links should return the reusable block payload."""

    app = create_application()

    class _FakeProtectedLinksService:
        async def resolve_redirect(self, **kwargs) -> ProtectedRedirectOutcome:
            assert kwargs["token"] == "danger-token"
            return _build_outcome(token="danger-token", allowed=False)

    app.dependency_overrides[get_protected_links_service] = lambda: _FakeProtectedLinksService()

    with TestClient(app) as client:
        response = client.get("/go/danger-token", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 403
    body = response.json()
    assert body["allowed"] is False
    assert body["reason"] == "Blocked by risk policy."
    assert body["analysis"]["risk_level"] == "danger"


def test_go_route_returns_404_for_invalid_token() -> None:
    """Unknown protected-link tokens should return a structured error payload."""

    app = create_application()

    class _FakeProtectedLinksService:
        async def resolve_redirect(self, **kwargs) -> ProtectedRedirectOutcome:
            raise ProtectedLinkNotFoundError(kwargs["token"])

    app.dependency_overrides[get_protected_links_service] = lambda: _FakeProtectedLinksService()

    with TestClient(app) as client:
        response = client.get("/go/missing-token", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["error"]["code"] == "protected_link_not_found"
    assert body["error"]["details"]["token"] == "missing-token"
