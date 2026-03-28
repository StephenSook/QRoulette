"""Tests for the typed Supabase repository layer."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
from fastapi.testclient import TestClient
import pytest

from app.api.deps import get_supabase_repository
from app.core.app import create_application
from app.core.config import Settings
from app.schemas.dashboard import DashboardOverviewResponse
from app.schemas.protected_links import ProtectedLinkRecord
from app.schemas.repository import (
    AlertsListParams,
    CreateProtectedLinkInput,
    ProtectedLinksListParams,
)
from app.services.base import ServiceContext
from app.services.supabase_repo import SupabaseRepository


class _FakeResponse:
    def __init__(self, data):
        self.data = data


class _FakeTableQuery:
    def __init__(self, tables: dict[str, list[dict]], name: str):
        self.tables = tables
        self.name = name
        self.insert_payload: dict | None = None
        self.filters: list[tuple[str, str, object]] = []
        self.ordering: tuple[str, bool] | None = None
        self.limit_value: int | None = None

    def insert(self, payload: dict):
        self.insert_payload = payload
        return self

    def select(self, _columns: str):
        return self

    def eq(self, column: str, value: object):
        self.filters.append(("eq", column, value))
        return self

    def gte(self, column: str, value: object):
        self.filters.append(("gte", column, value))
        return self

    def in_(self, column: str, values: list[object]):
        self.filters.append(("in", column, values))
        return self

    def order(self, column: str, desc: bool = False):
        self.ordering = (column, desc)
        return self

    def limit(self, value: int):
        self.limit_value = value
        return self

    def execute(self):
        rows = self.tables.setdefault(self.name, [])
        if self.insert_payload is not None:
            row = dict(self.insert_payload)
            row.setdefault("id", f"{self.name}_{len(rows) + 1}")
            row.setdefault("created_at", datetime.now(UTC).isoformat())
            rows.append(row)
            return _FakeResponse([row])

        result = list(rows)
        for operation, column, value in self.filters:
            if operation == "eq":
                result = [row for row in result if row.get(column) == value]
            elif operation == "gte":
                result = [row for row in result if row.get(column) >= value]
            elif operation == "in":
                result = [row for row in result if row.get(column) in value]
        if self.ordering is not None:
            column, desc = self.ordering
            result.sort(key=lambda row: row.get(column), reverse=desc)
        if self.limit_value is not None:
            result = result[: self.limit_value]
        return _FakeResponse(result)


class _FakeSupabaseClient:
    def __init__(self, tables: dict[str, list[dict]]):
        self.tables = tables

    def table(self, name: str) -> _FakeTableQuery:
        return _FakeTableQuery(self.tables, name)


def _build_repository(tables: dict[str, list[dict]]) -> tuple[SupabaseRepository, ServiceContext]:
    context = ServiceContext(client=httpx.AsyncClient(), settings=Settings())
    repository = SupabaseRepository(context)
    repository._client = _FakeSupabaseClient(tables)
    return repository, context


@pytest.mark.anyio
async def test_save_scan_result_splits_event_and_analysis_rows() -> None:
    """Compatibility persistence should write to scan_events and scan_analyses."""

    repository, context = _build_repository({})
    try:
        result = await repository.save_scan_result(
            {
                "scanned_url": "https://example.com/login",
                "normalized_url": "https://example.com/login",
                "registrable_domain": "example.com",
                "risk_score": 91,
                "risk_level": "danger",
                "flagged_safe_browsing": True,
                "flagged_threat_intel": False,
                "typosquatting_detected": False,
                "domain_age_days": 10,
                "redirect_hops": 2,
                "ssl_valid": True,
                "ai_summary": "blocked",
                "analysis_payload": {"scan_id": "scan_123"},
                "protected_link_id": "plink_123",
                "organization_id": "org_123",
                "ip_address": "1.2.3.4",
            }
        )
    finally:
        await context.client.aclose()

    assert result.persisted is True
    assert result.record_id == "scan_analyses_1"
    assert result.raw_response["scan_event"]["protected_link_id"] == "plink_123"
    assert result.raw_response["scan_analysis"]["scan_event_id"] == "scan_events_1"


@pytest.mark.anyio
async def test_repository_queries_return_typed_results() -> None:
    """The repository should map list and lookup queries into typed models."""

    created_recently = datetime.now(UTC).isoformat()
    older = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    tables = {
        "protected_links": [
            {
                "id": "plink_1",
                "token": "tok_1",
                "original_url": "example.com",
                "normalized_url": "https://example.com",
                "label": "Front Door",
                "organization_id": "org_123",
                "is_active": True,
                "created_at": created_recently,
            }
        ],
        "scan_events": [
            {
                "id": "event_1",
                "created_at": created_recently,
                "organization_id": "org_123",
                "protected_link_id": "plink_1",
                "qr_code_id": "plink_1",
                "protected_link_token": "tok_1",
                "protected_link_label": "Front Door",
                "scanned_url": "https://example.com",
                "normalized_url": "https://example.com",
                "registrable_domain": "example.com",
                "ip_address": "1.2.3.4",
                "user_agent": "pytest",
                "country": "US",
            }
        ],
        "scan_analyses": [
            {
                "id": "analysis_1",
                "created_at": created_recently,
                "scan_event_id": "event_1",
                "organization_id": "org_123",
                "protected_link_id": "plink_1",
                "qr_code_id": "plink_1",
                "registrable_domain": "example.com",
                "risk_score": 12,
                "risk_level": "safe",
                "flagged_safe_browsing": False,
                "flagged_threat_intel": False,
                "typosquatting_detected": False,
                "domain_age_days": 100,
                "redirect_hops": 0,
                "ssl_valid": True,
                "ai_summary": "ok",
                "analysis_payload": {"scan_id": "scan_123"},
            },
            {
                "id": "analysis_old",
                "created_at": older,
                "scan_event_id": "event_old",
                "organization_id": "org_123",
                "protected_link_id": "plink_1",
                "qr_code_id": "plink_1",
                "registrable_domain": "old.example.com",
                "risk_score": 99,
                "risk_level": "danger",
                "flagged_safe_browsing": True,
                "flagged_threat_intel": False,
                "typosquatting_detected": False,
                "domain_age_days": 1,
                "redirect_hops": 4,
                "ssl_valid": True,
                "ai_summary": "old",
                "analysis_payload": {"scan_id": "scan_old"},
            },
        ],
        "alerts": [
            {
                "id": "alert_1",
                "created_at": created_recently,
                "organization_id": "org_123",
                "protected_link_id": "plink_1",
                "scan_event_id": "event_1",
                "scan_analysis_id": "analysis_1",
                "severity": "warning",
                "status": "open",
                "title": "Suspicious scan",
                "message": "Review this destination",
                "metadata": {"source": "rules"},
            }
        ],
    }
    repository, context = _build_repository(tables)
    try:
        created = await repository.create_protected_link(
            CreateProtectedLinkInput(
                token="tok_2",
                original_url="https://example.org",
                normalized_url="https://example.org",
                label="Kitchen",
                organization_id="org_123",
            )
        )
        looked_up = await repository.get_protected_link_by_token("tok_1")
        overview = await repository.get_dashboard_overview(days=7)
        recent = await repository.list_recent_scans(limit=10)
        links = await repository.list_protected_links(
            ProtectedLinksListParams(organization_id="org_123")
        )
        alerts = await repository.list_alerts(
            AlertsListParams(organization_id="org_123", status="open")
        )
    finally:
        await context.client.aclose()

    assert isinstance(created, ProtectedLinkRecord)
    assert looked_up is not None and looked_up.token == "tok_1"
    assert overview.metrics.total_scans == 1
    assert overview.metrics.safe_count == 1
    assert overview.metrics.latest_verdict == "safe"
    assert recent[0].protected_link_label == "Front Door"
    assert len(links) == 2
    assert alerts[0].title == "Suspicious scan"


def test_dashboard_route_uses_repository_overview_query() -> None:
    """The dashboard route should delegate to the repository method."""

    app = create_application()

    class _FakeRepository:
        async def get_dashboard_overview(self, days: int = 7) -> DashboardOverviewResponse:
            assert days == 14
            return DashboardOverviewResponse(
                period_days=days,
                metrics={
                    "total_scans": 8,
                    "safe_count": 5,
                    "suspicious_count": 2,
                    "malicious_count": 1,
                    "unknown_count": 0,
                    "latest_verdict": "suspicious",
                },
                message="loaded",
            )

    app.dependency_overrides[get_supabase_repository] = lambda: _FakeRepository()

    with TestClient(app) as client:
        response = client.get("/api/dashboard/overview?days=14")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["metrics"]["total_scans"] == 8
    assert body["data"]["metrics"]["latest_verdict"] == "suspicious"
