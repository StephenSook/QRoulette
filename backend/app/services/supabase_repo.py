"""Supabase repository helpers."""

from __future__ import annotations

import asyncio
from typing import Any

from app.core.logging import get_logger
from app.schemas.persistence import PersistenceResult
from app.services.base import ServiceStub


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

    async def save_scan_result(self, payload: dict[str, Any]) -> PersistenceResult:
        """Persist a scan record when Supabase is configured."""

        client = self._build_client()
        if client is None:
            self.logger.info("Supabase persistence skipped because credentials are missing.")
            return PersistenceResult(
                available=False,
                persisted=False,
                error="Supabase is not configured.",
            )

        try:
            response = await asyncio.to_thread(
                lambda: client.table("scans").insert(payload).execute()
            )
        except Exception as exc:  # pragma: no cover - client exceptions vary by SDK version
            self.logger.error("Supabase scan persistence failed: %s", exc)
            return PersistenceResult(
                available=True,
                persisted=False,
                error="Supabase scan persistence failed.",
            )

        rows = response.data or []
        if not rows:
            return PersistenceResult(
                available=True,
                persisted=False,
                error="Supabase returned no inserted row.",
                raw_response={"data": rows},
            )

        row = rows[0]
        record_id = row.get("id") if isinstance(row, dict) else None
        return PersistenceResult(
            available=True,
            persisted=True,
            record_id=str(record_id) if record_id is not None else None,
            raw_response={"data": rows},
        )

    async def fetch_dashboard_summary(self) -> dict:
        """Return dashboard data from persistence."""

        await self.not_implemented("dashboard summary persistence")
