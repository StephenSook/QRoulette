"""Supabase repository helpers.

Example migration SQL for the repository tables:

```sql
create table if not exists organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text unique,
  created_at timestamptz not null default now()
);

create table if not exists protected_links (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid references organizations(id) on delete set null,
  token text not null unique,
  original_url text not null,
  normalized_url text not null,
  label text not null,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists scan_events (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid references organizations(id) on delete set null,
  protected_link_id uuid references protected_links(id) on delete set null,
  qr_code_id text,
  protected_link_token text,
  protected_link_label text,
  scanned_url text not null,
  normalized_url text,
  registrable_domain text,
  ip_address text,
  user_agent text,
  country text,
  created_at timestamptz not null default now()
);

create table if not exists scan_analyses (
  id uuid primary key default gen_random_uuid(),
  scan_event_id uuid references scan_events(id) on delete cascade,
  organization_id uuid references organizations(id) on delete set null,
  protected_link_id uuid references protected_links(id) on delete set null,
  qr_code_id text,
  registrable_domain text,
  risk_score integer,
  risk_level text,
  flagged_safe_browsing boolean not null default false,
  flagged_threat_intel boolean not null default false,
  typosquatting_detected boolean not null default false,
  domain_age_days integer,
  redirect_hops integer,
  ssl_valid boolean,
  ai_summary text,
  analysis_payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists alerts (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid references organizations(id) on delete set null,
  protected_link_id uuid references protected_links(id) on delete set null,
  scan_event_id uuid references scan_events(id) on delete set null,
  scan_analysis_id uuid references scan_analyses(id) on delete set null,
  severity text not null default 'warning',
  status text not null default 'open',
  title text not null,
  message text not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_protected_links_token on protected_links(token);
create index if not exists idx_protected_links_org_created on protected_links(organization_id, created_at desc);
create index if not exists idx_scan_events_created on scan_events(created_at desc);
create index if not exists idx_scan_events_org_created on scan_events(organization_id, created_at desc);
create index if not exists idx_scan_analyses_created on scan_analyses(created_at desc);
create index if not exists idx_scan_analyses_event on scan_analyses(scan_event_id);
create index if not exists idx_scan_analyses_org_created on scan_analyses(organization_id, created_at desc);
create index if not exists idx_alerts_org_created on alerts(organization_id, created_at desc);
```
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any, Callable

from app.core.logging import get_logger
from app.schemas.dashboard import DashboardOverviewMetrics, DashboardOverviewResponse
from app.schemas.enums import Verdict
from app.schemas.persistence import PersistenceResult
from app.schemas.protected_links import ProtectedLinkRecord
from app.schemas.repository import (
    AlertRecord,
    AlertsListParams,
    CreateProtectedLinkInput,
    CreateScanAnalysisInput,
    CreateScanEventInput,
    ProtectedLinksListParams,
    RecentScanRecord,
    ScanAnalysisRecord,
    ScanEventRecord,
)
from app.services.base import ServiceStub

PROTECTED_LINK_COLUMNS = (
    "id, token, original_url, normalized_url, label, organization_id, is_active, created_at"
)
SCAN_EVENT_COLUMNS = (
    "id, created_at, organization_id, protected_link_id, qr_code_id, "
    "protected_link_token, protected_link_label, scanned_url, normalized_url, "
    "registrable_domain, ip_address, user_agent, country"
)
SCAN_ANALYSIS_COLUMNS = (
    "id, created_at, scan_event_id, organization_id, protected_link_id, qr_code_id, "
    "registrable_domain, risk_score, risk_level, flagged_safe_browsing, "
    "flagged_threat_intel, typosquatting_detected, domain_age_days, redirect_hops, "
    "ssl_valid, ai_summary, analysis_payload"
)
ALERT_COLUMNS = (
    "id, created_at, organization_id, protected_link_id, scan_event_id, "
    "scan_analysis_id, severity, status, title, message, metadata"
)


class SupabaseRepository(ServiceStub):
    """Persist and retrieve application records from Supabase."""

    def __init__(self, context) -> None:
        super().__init__(context)
        self.logger = get_logger("qroulette.supabase")
        self._client = None

    def _build_client(self):
        """Create a lazy Supabase client only when configuration exists."""

        if self._client is not None:
            return self._client

        url = self.context.settings.supabase_url
        key = (
            self.context.settings.supabase_service_role_key
            or self.context.settings.supabase_key
        )
        if not url or not key:
            return None

        from supabase import create_client

        self._client = create_client(url, key)
        return self._client

    def _require_client(self):
        """Return a configured Supabase client or raise a runtime error."""

        client = self._build_client()
        if client is None:
            raise RuntimeError("Supabase is not configured.")
        return client

    async def _run(self, operation: Callable[[], Any]) -> Any:
        """Execute a synchronous Supabase operation in a worker thread."""

        return await asyncio.to_thread(operation)

    async def _insert_one(self, table: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Insert a row and return the inserted record."""

        client = self._require_client()
        response = await self._run(lambda: client.table(table).insert(payload).execute())
        rows = response.data or []
        if not rows:
            raise RuntimeError(f"Supabase returned no inserted row for {table}.")
        return rows[0]

    @staticmethod
    def _raw_url(value: Any) -> str | None:
        """Normalize URL-like values from persistence payloads."""

        return None if value is None else str(value)

    @staticmethod
    def _to_verdict(value: str | None) -> Verdict:
        """Map persisted risk levels into dashboard verdicts."""

        normalized = (value or "").lower()
        if normalized == "safe":
            return Verdict.SAFE
        if normalized == "suspicious":
            return Verdict.SUSPICIOUS
        if normalized in {"danger", "dangerous", "malicious"}:
            return Verdict.MALICIOUS
        return Verdict.UNKNOWN

    def _event_summary_row(self, payload: dict[str, Any]) -> CreateScanEventInput:
        """Translate a combined scan payload into a scan event input."""

        return CreateScanEventInput(
            organization_id=payload.get("organization_id"),
            protected_link_id=payload.get("protected_link_id") or payload.get("qr_code_id"),
            qr_code_id=payload.get("qr_code_id") or payload.get("protected_link_id"),
            protected_link_token=payload.get("protected_link_token"),
            protected_link_label=payload.get("protected_link_label"),
            scanned_url=str(payload.get("scanned_url") or ""),
            normalized_url=self._raw_url(payload.get("normalized_url")),
            registrable_domain=payload.get("registrable_domain"),
            ip_address=payload.get("ip_address"),
            user_agent=payload.get("user_agent"),
            country=payload.get("country"),
        )

    def _analysis_summary_row(self, payload: dict[str, Any]) -> CreateScanAnalysisInput:
        """Translate a combined scan payload into a scan analysis input."""

        return CreateScanAnalysisInput(
            organization_id=payload.get("organization_id"),
            protected_link_id=payload.get("protected_link_id") or payload.get("qr_code_id"),
            qr_code_id=payload.get("qr_code_id") or payload.get("protected_link_id"),
            registrable_domain=payload.get("registrable_domain"),
            risk_score=payload.get("risk_score"),
            risk_level=payload.get("risk_level"),
            flagged_safe_browsing=bool(payload.get("flagged_safe_browsing", False)),
            flagged_threat_intel=bool(payload.get("flagged_threat_intel", False)),
            typosquatting_detected=bool(payload.get("typosquatting_detected", False)),
            domain_age_days=payload.get("domain_age_days"),
            redirect_hops=payload.get("redirect_hops"),
            ssl_valid=payload.get("ssl_valid"),
            ai_summary=payload.get("ai_summary"),
            analysis_payload=payload.get("analysis_payload") or {},
        )

    async def save_scan_result(self, payload: dict[str, Any]) -> PersistenceResult:
        """Persist a scan result using split event and analysis tables."""

        if self._build_client() is None:
            self.logger.info("Supabase persistence skipped because credentials are missing.")
            return PersistenceResult(
                available=False,
                persisted=False,
                error="Supabase is not configured.",
            )

        try:
            scan_event = await self.create_scan_event(self._event_summary_row(payload))
            scan_analysis_input = self._analysis_summary_row(payload)
            scan_analysis = await self.create_scan_analysis(
                scan_analysis_input.model_copy(update={"scan_event_id": scan_event.id})
            )
        except Exception as exc:  # pragma: no cover - SDK exceptions vary by version
            self.logger.error("Supabase scan persistence failed: %s", exc)
            return PersistenceResult(
                available=True,
                persisted=False,
                error="Supabase scan persistence failed.",
            )

        return PersistenceResult(
            available=True,
            persisted=True,
            record_id=scan_analysis.id,
            raw_response={
                "scan_event": scan_event.model_dump(mode="json"),
                "scan_analysis": scan_analysis.model_dump(mode="json"),
            },
        )

    async def fetch_dashboard_summary(self) -> dict[str, int]:
        """Return the legacy dashboard summary payload."""

        overview = await self.get_dashboard_overview(days=7)
        return {
            "safe": overview.metrics.safe_count,
            "suspicious": overview.metrics.suspicious_count,
            "danger": overview.metrics.malicious_count,
            "total": overview.metrics.total_scans,
        }

    async def create_protected_link(
        self,
        payload: CreateProtectedLinkInput,
    ) -> ProtectedLinkRecord:
        """Persist a protected-link record and return the saved row."""

        # TODO: Add org-scoped RLS so organizations can only create links for themselves.
        row = await self._insert_one(
            "protected_links",
            payload.model_dump(mode="json"),
        )
        return ProtectedLinkRecord.model_validate(row)

    async def get_protected_link_by_token(self, token: str) -> ProtectedLinkRecord | None:
        """Fetch a protected-link record by token."""

        client = self._require_client()
        # TODO: If token resolution becomes public/anon traffic, add a narrow read policy for active links only.
        response = await self._run(
            lambda: client.table("protected_links")
            .select(PROTECTED_LINK_COLUMNS)
            .eq("token", token)
            .limit(1)
            .execute()
        )
        rows = response.data or []
        if not rows:
            return None
        return ProtectedLinkRecord.model_validate(rows[0])

    async def create_scan_event(self, payload: CreateScanEventInput) -> ScanEventRecord:
        """Persist a scan event row."""

        # TODO: Restrict insert access with service-role or backend-only RLS policies.
        row = await self._insert_one(
            "scan_events",
            payload.model_dump(mode="json"),
        )
        return ScanEventRecord.model_validate(row)

    async def create_scan_analysis(
        self,
        payload: CreateScanAnalysisInput,
    ) -> ScanAnalysisRecord:
        """Persist a scan analysis row."""

        # TODO: Restrict insert access with service-role or backend-only RLS policies.
        row = await self._insert_one(
            "scan_analyses",
            payload.model_dump(mode="json"),
        )
        return ScanAnalysisRecord.model_validate(row)

    async def get_dashboard_overview(self, days: int = 7) -> DashboardOverviewResponse:
        """Aggregate scan analysis rows for the dashboard overview."""

        client = self._build_client()
        if client is None:
            return DashboardOverviewResponse(
                period_days=days,
                metrics=DashboardOverviewMetrics(),
                message="Supabase is not configured.",
            )

        since = datetime.now(UTC) - timedelta(days=days)
        # TODO: Add organization-scoped RLS before serving this to user-scoped sessions.
        response = await self._run(
            lambda: client.table("scan_analyses")
            .select("risk_level, created_at")
            .gte("created_at", since.isoformat())
            .order("created_at", desc=True)
            .execute()
        )
        rows = response.data or []

        safe_count = 0
        suspicious_count = 0
        malicious_count = 0
        unknown_count = 0
        for row in rows:
            verdict = self._to_verdict(row.get("risk_level"))
            if verdict == Verdict.SAFE:
                safe_count += 1
            elif verdict == Verdict.SUSPICIOUS:
                suspicious_count += 1
            elif verdict == Verdict.MALICIOUS:
                malicious_count += 1
            else:
                unknown_count += 1

        latest_verdict = self._to_verdict(rows[0].get("risk_level") if rows else None)
        return DashboardOverviewResponse(
            period_days=days,
            metrics=DashboardOverviewMetrics(
                total_scans=len(rows),
                safe_count=safe_count,
                suspicious_count=suspicious_count,
                malicious_count=malicious_count,
                unknown_count=unknown_count,
                latest_verdict=latest_verdict,
            ),
            message="Dashboard overview loaded from Supabase.",
        )

    async def list_recent_scans(self, limit: int = 25) -> list[RecentScanRecord]:
        """Return newest-first scan records joined from events and analyses."""

        client = self._build_client()
        if client is None:
            return []

        # TODO: Add organization-scoped RLS before exposing recent scans to end-user sessions.
        response = await self._run(
            lambda: client.table("scan_events")
            .select(SCAN_EVENT_COLUMNS)
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        event_rows = response.data or []
        events = [ScanEventRecord.model_validate(row) for row in event_rows]
        if not events:
            return []

        event_ids = [event.id for event in events]
        analyses_response = await self._run(
            lambda: client.table("scan_analyses")
            .select(SCAN_ANALYSIS_COLUMNS)
            .in_("scan_event_id", event_ids)
            .order("created_at", desc=True)
            .execute()
        )
        analyses = [
            ScanAnalysisRecord.model_validate(row)
            for row in (analyses_response.data or [])
        ]
        latest_by_event: dict[str, ScanAnalysisRecord] = {}
        for analysis in analyses:
            if analysis.scan_event_id and analysis.scan_event_id not in latest_by_event:
                latest_by_event[analysis.scan_event_id] = analysis

        records: list[RecentScanRecord] = []
        for event in events:
            analysis = latest_by_event.get(event.id)
            records.append(
                RecentScanRecord(
                    id=analysis.id if analysis else event.id,
                    created_at=analysis.created_at or event.created_at or datetime.now(UTC),
                    scanned_url=event.scanned_url,
                    qr_code_id=event.qr_code_id,
                    risk_score=analysis.risk_score if analysis else None,
                    risk_level=analysis.risk_level if analysis else None,
                    flagged_safe_browsing=analysis.flagged_safe_browsing if analysis else False,
                    flagged_threat_intel=analysis.flagged_threat_intel if analysis else False,
                    typosquatting_detected=analysis.typosquatting_detected if analysis else False,
                    domain_age_days=analysis.domain_age_days if analysis else None,
                    redirect_hops=analysis.redirect_hops if analysis else None,
                    ssl_valid=analysis.ssl_valid if analysis else None,
                    ai_summary=analysis.ai_summary if analysis else None,
                    ip_address=event.ip_address,
                    user_agent=event.user_agent,
                    country=event.country,
                    protected_link_id=event.protected_link_id,
                    protected_link_token=event.protected_link_token,
                    protected_link_label=event.protected_link_label,
                )
            )
        return records

    async def list_protected_links(
        self,
        params: ProtectedLinksListParams | None = None,
    ) -> list[ProtectedLinkRecord]:
        """Return protected links with optional organization/activity filters."""

        query_params = params or ProtectedLinksListParams()
        client = self._build_client()
        if client is None:
            return []

        query = (
            client.table("protected_links")
            .select(PROTECTED_LINK_COLUMNS)
            .order("created_at", desc=True)
            .limit(query_params.limit)
        )
        if query_params.organization_id:
            query = query.eq("organization_id", query_params.organization_id)
        if query_params.is_active is not None:
            query = query.eq("is_active", query_params.is_active)

        # TODO: Enforce organization-level RLS before exposing link lists to organization members.
        response = await self._run(lambda: query.execute())
        return [ProtectedLinkRecord.model_validate(row) for row in (response.data or [])]

    async def list_alerts(
        self,
        params: AlertsListParams | None = None,
    ) -> list[AlertRecord]:
        """Return newest-first alerts with optional filters."""

        query_params = params or AlertsListParams()
        client = self._build_client()
        if client is None:
            return []

        query = (
            client.table("alerts")
            .select(ALERT_COLUMNS)
            .order("created_at", desc=True)
            .limit(query_params.limit)
        )
        if query_params.organization_id:
            query = query.eq("organization_id", query_params.organization_id)
        if query_params.status:
            query = query.eq("status", query_params.status)

        # TODO: Enforce organization-level RLS before exposing alert feeds to organization members.
        response = await self._run(lambda: query.execute())
        return [AlertRecord.model_validate(row) for row in (response.data or [])]
