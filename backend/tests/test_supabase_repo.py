"""Tests for the typed Supabase repository layer."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
from fastapi.testclient import TestClient
import pytest

from app.api.deps import get_supabase_repository
from app.core.app import create_application
from app.core.config import Settings
from app.schemas.dashboard import (
    DashboardAlertsResponse,
    DashboardLinksResponse,
    DashboardOverviewResponse,
    DashboardScansQuery,
    DashboardScansResponse,
)
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

    def lte(self, column: str, value: object):
        self.filters.append(("lte", column, value))
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
            elif operation == "lte":
                result = [row for row in result if row.get(column) <= value]
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
    within_hour = (datetime.now(UTC) - timedelta(minutes=30)).isoformat()
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
            },
            {
                "id": "plink_2",
                "token": "tok_2",
                "original_url": "danger.example.com",
                "normalized_url": "https://danger.example.com",
                "label": "Warehouse",
                "organization_id": "org_123",
                "is_active": True,
                "created_at": created_recently,
            },
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
            },
            {
                "id": "event_2",
                "created_at": created_recently,
                "organization_id": "org_123",
                "protected_link_id": "plink_2",
                "qr_code_id": "plink_2",
                "protected_link_token": "tok_2",
                "protected_link_label": "Warehouse",
                "scanned_url": "https://danger.example.com/login",
                "normalized_url": "https://danger.example.com/login",
                "registrable_domain": "danger.example.com",
                "ip_address": "1.2.3.5",
                "user_agent": "pytest",
                "country": "US",
            },
            {
                "id": "event_3",
                "created_at": within_hour,
                "organization_id": "org_123",
                "protected_link_id": "plink_2",
                "qr_code_id": "plink_2",
                "protected_link_token": "tok_2",
                "protected_link_label": "Warehouse",
                "scanned_url": "https://danger.example.com/pay",
                "normalized_url": "https://danger.example.com/pay",
                "registrable_domain": "danger.example.com",
                "ip_address": "1.2.3.6",
                "user_agent": "pytest",
                "country": "US",
            },
            {
                "id": "event_4",
                "created_at": within_hour,
                "organization_id": "org_123",
                "protected_link_id": "plink_2",
                "qr_code_id": "plink_2",
                "protected_link_token": "tok_2",
                "protected_link_label": "Warehouse",
                "scanned_url": "https://danger.example.com/reset",
                "normalized_url": "https://danger.example.com/reset",
                "registrable_domain": "danger.example.com",
                "ip_address": "1.2.3.7",
                "user_agent": "pytest",
                "country": "US",
            },
            {
                "id": "event_5",
                "created_at": within_hour,
                "organization_id": "org_123",
                "protected_link_id": "plink_2",
                "qr_code_id": "plink_2",
                "protected_link_token": "tok_2",
                "protected_link_label": "Warehouse",
                "scanned_url": "https://danger.example.com/update",
                "normalized_url": "https://danger.example.com/update",
                "registrable_domain": "danger.example.com",
                "ip_address": "1.2.3.8",
                "user_agent": "pytest",
                "country": "US",
            },
            {
                "id": "event_6",
                "created_at": within_hour,
                "organization_id": "org_123",
                "protected_link_id": "plink_2",
                "qr_code_id": "plink_2",
                "protected_link_token": "tok_2",
                "protected_link_label": "Warehouse",
                "scanned_url": "https://danger.example.com/verify",
                "normalized_url": "https://danger.example.com/verify",
                "registrable_domain": "danger.example.com",
                "ip_address": "1.2.3.9",
                "user_agent": "pytest",
                "country": "US",
            },
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
                "id": "analysis_2",
                "created_at": created_recently,
                "scan_event_id": "event_2",
                "organization_id": "org_123",
                "protected_link_id": "plink_2",
                "qr_code_id": "plink_2",
                "registrable_domain": "danger.example.com",
                "risk_score": 95,
                "risk_level": "danger",
                "flagged_safe_browsing": True,
                "flagged_threat_intel": False,
                "typosquatting_detected": False,
                "domain_age_days": 1,
                "redirect_hops": 2,
                "ssl_valid": True,
                "ai_summary": "danger",
                "analysis_payload": {"scan_id": "scan_234"},
            },
            {
                "id": "analysis_3",
                "created_at": within_hour,
                "scan_event_id": "event_3",
                "organization_id": "org_123",
                "protected_link_id": "plink_2",
                "qr_code_id": "plink_2",
                "registrable_domain": "danger.example.com",
                "risk_score": 98,
                "risk_level": "danger",
                "flagged_safe_browsing": True,
                "flagged_threat_intel": False,
                "typosquatting_detected": False,
                "domain_age_days": 1,
                "redirect_hops": 3,
                "ssl_valid": True,
                "ai_summary": "danger",
                "analysis_payload": {"scan_id": "scan_235"},
            },
            {
                "id": "analysis_4",
                "created_at": within_hour,
                "scan_event_id": "event_4",
                "organization_id": "org_123",
                "protected_link_id": "plink_2",
                "qr_code_id": "plink_2",
                "registrable_domain": "danger.example.com",
                "risk_score": 99,
                "risk_level": "danger",
                "flagged_safe_browsing": True,
                "flagged_threat_intel": False,
                "typosquatting_detected": False,
                "domain_age_days": 1,
                "redirect_hops": 4,
                "ssl_valid": True,
                "ai_summary": "danger",
                "analysis_payload": {"scan_id": "scan_236"},
            },
            {
                "id": "analysis_5",
                "created_at": within_hour,
                "scan_event_id": "event_5",
                "organization_id": "org_123",
                "protected_link_id": "plink_2",
                "qr_code_id": "plink_2",
                "registrable_domain": "danger.example.com",
                "risk_score": 92,
                "risk_level": "danger",
                "flagged_safe_browsing": True,
                "flagged_threat_intel": False,
                "typosquatting_detected": False,
                "domain_age_days": 1,
                "redirect_hops": 2,
                "ssl_valid": True,
                "ai_summary": "danger",
                "analysis_payload": {"scan_id": "scan_237"},
            },
            {
                "id": "analysis_6",
                "created_at": within_hour,
                "scan_event_id": "event_6",
                "organization_id": "org_123",
                "protected_link_id": "plink_2",
                "qr_code_id": "plink_2",
                "registrable_domain": "danger.example.com",
                "risk_score": 93,
                "risk_level": "danger",
                "flagged_safe_browsing": True,
                "flagged_threat_intel": False,
                "typosquatting_detected": False,
                "domain_age_days": 1,
                "redirect_hops": 2,
                "ssl_valid": True,
                "ai_summary": "danger",
                "analysis_payload": {"scan_id": "scan_238"},
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
                token="tok_3",
                original_url="https://example.org",
                normalized_url="https://example.org",
                label="Kitchen",
                organization_id="org_123",
            )
        )
        looked_up = await repository.get_protected_link_by_token("tok_1")
        overview = await repository.get_dashboard_overview(days=7)
        recent = await repository.list_recent_scans(limit=10)
        filtered_recent = await repository.list_recent_scans(
            DashboardScansQuery(verdict="danger", domain="danger.example.com", limit=10)
        )
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
    assert overview.metrics.total_scans == 6
    assert overview.metrics.safe_count == 1
    assert overview.metrics.dangerous_count == 5
    assert overview.metrics.latest_verdict == "safe"
    assert overview.metrics.recent_activity.last_24h_total == 6
    assert recent[0].protected_link_label == "Front Door"
    assert all(item.risk_level == "danger" for item in filtered_recent)
    assert len(filtered_recent) == 5
    assert len(links) == 3
    warehouse = next(item for item in links if item.id == "plink_2")
    assert warehouse.scan_count == 5
    assert warehouse.dangerous_scan_count == 5
    assert alerts[0].source in {"persisted", "derived"}
    assert any(item.source == "derived" for item in alerts)


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
                    "dangerous_count": 1,
                    "unknown_count": 0,
                    "latest_verdict": "suspicious",
                    "recent_activity": {
                        "last_24h_total": 4,
                        "last_24h_safe": 2,
                        "last_24h_suspicious": 1,
                        "last_24h_dangerous": 1,
                    },
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
    assert body["data"]["metrics"]["recent_activity"]["last_24h_total"] == 4


def test_dashboard_routes_return_scans_links_and_alerts() -> None:
    """Dashboard list routes should return frontend-friendly JSON."""

    app = create_application()

    class _FakeRepository:
        async def list_recent_scans(self, params):
            assert params.verdict == "danger"
            return [
                {
                    "id": "scan_1",
                    "created_at": datetime.now(UTC),
                    "scanned_url": "https://danger.example.com",
                    "qr_code_id": "plink_1",
                    "risk_level": "danger",
                    "registrable_domain": "danger.example.com",
                }
            ]

        async def list_protected_links(self, params):
            assert params.limit == 10
            return [
                {
                    "id": "plink_1",
                    "token": "tok_1",
                    "original_url": "https://example.com",
                    "normalized_url": "https://example.com",
                    "label": "Front Door",
                    "organization_id": "org_123",
                    "is_active": True,
                    "scan_count": 7,
                    "dangerous_scan_count": 2,
                    "suspicious_scan_count": 1,
                    "last_scanned_at": datetime.now(UTC),
                }
            ]

        async def list_alerts(self, params):
            assert params.limit == 10
            return [
                {
                    "id": "alert_1",
                    "created_at": datetime.now(UTC),
                    "source": "derived",
                    "alert_type": "dangerous_scan_spike",
                    "severity": "critical",
                    "status": "open",
                    "title": "Dangerous scan spike detected",
                    "message": "Five or more dangerous scans were observed in the last hour.",
                    "count": 5,
                    "metadata": {"window": "1h"},
                }
            ]

    app.dependency_overrides[get_supabase_repository] = lambda: _FakeRepository()

    with TestClient(app) as client:
        scans_response = client.get("/api/dashboard/scans?verdict=danger")
        links_response = client.get("/api/dashboard/links?limit=10")
        alerts_response = client.get("/api/dashboard/alerts?limit=10")

    app.dependency_overrides.clear()

    assert scans_response.status_code == 200
    assert scans_response.json()["data"]["total"] == 1
    assert scans_response.json()["data"]["items"][0]["registrable_domain"] == "danger.example.com"

    assert links_response.status_code == 200
    assert links_response.json()["data"]["items"][0]["scan_count"] == 7

    assert alerts_response.status_code == 200
    alerts_body = alerts_response.json()
    assert alerts_body["data"]["items"][0]["source"] == "derived"
    assert alerts_body["data"]["items"][0]["count"] == 5
