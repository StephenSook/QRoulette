from typing import Any

from db.supabase_client import supabase
from models.contracts import DashboardSummaryResponse, ScanRecord


def log_scan(scan_data: dict[str, Any]) -> dict[str, Any]:
    # Writes one scan event to Supabase for later dashboard analysis.
    response = supabase.table("scans").insert(scan_data).execute()
    if not response.data:
        raise RuntimeError("Supabase insert failed for scans table.")
    return response.data[0]


def get_recent_scans(limit: int = 25) -> list[ScanRecord]:
    # Newest-first feed powers the dashboard "recent activity" list.
    response = (
        supabase.table("scans")
        .select("*")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    rows = response.data or []
    return [ScanRecord.model_validate(row) for row in rows]


def get_risk_totals() -> DashboardSummaryResponse:
    # Keep aggregation in backend so frontend stays thin and consistent.
    response = supabase.table("scans").select("risk_level").execute()
    rows = response.data or []
    safe = sum(1 for row in rows if row.get("risk_level") == "safe")
    suspicious = sum(1 for row in rows if row.get("risk_level") == "suspicious")
    danger = sum(1 for row in rows if row.get("risk_level") == "danger")
    return DashboardSummaryResponse(
        safe=safe,
        suspicious=suspicious,
        danger=danger,
        total=len(rows),
    )
