import os
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()


def _parse_datetime(value: Any) -> datetime | None:
    """Best-effort parser for provider date fields."""
    if isinstance(value, list):
        for item in value:
            parsed = _parse_datetime(item)
            if parsed is not None:
                return parsed
        return None

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)

    if not isinstance(value, str):
        return None

    normalized = value.strip()
    if not normalized:
        return None

    candidates = [normalized]
    if normalized.endswith("Z"):
        candidates.append(normalized[:-1] + "+00:00")

    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(normalized, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    try:
        parsed = parsedate_to_datetime(normalized)
    except (TypeError, ValueError, IndexError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _extract_created_date(payload: dict[str, Any]) -> datetime | None:
    """Extract creation date from common WhoisXML response shapes."""
    record = payload.get("WhoisRecord") or payload.get("whoisRecord") or {}
    if not isinstance(record, dict):
        return None

    candidates: list[Any] = [
        record.get("createdDateNormalized"),
        record.get("createdDate"),
    ]
    registry_data = record.get("registryData")
    if isinstance(registry_data, dict):
        candidates.extend(
            [
                registry_data.get("createdDateNormalized"),
                registry_data.get("createdDate"),
            ]
        )

    for value in candidates:
        parsed = _parse_datetime(value)
        if parsed is not None:
            return parsed
    return None


def get_domain_age_days(hostname: str) -> int | None:
    """
    Return domain age in days when data is available.

    Current lightweight implementation supports a local override map for demo/testing:
    WHOIS_MOCK_AGES="paypal.com:9000,fake-paypal-demo.com:1"
    """
    mapping = os.getenv("WHOIS_MOCK_AGES", "").strip()
    ages: dict[str, int] = {}
    if mapping:
        for item in mapping.split(","):
            if ":" not in item:
                continue
            host, days = item.split(":", 1)
            host = host.strip().lower()
            try:
                ages[host] = int(days.strip())
            except ValueError:
                continue

    host = hostname.lower().strip()
    if host in ages:
        return max(ages[host], 0)

    # Fallback override: derive days from a manually supplied timestamp.
    created_at = os.getenv("WHOIS_CREATED_AT")
    if created_at:
        try:
            created_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            return max((datetime.now(timezone.utc) - created_dt).days, 0)
        except ValueError:
            return None

    # Real provider lookup.
    api_key = os.getenv("WHOIS_XML_API_KEY", "").strip()
    if not api_key:
        return None

    base_url = os.getenv(
        "WHOIS_BASE_URL",
        "https://www.whoisxmlapi.com/whoisserver/WhoisService",
    ).strip()
    try:
        timeout_seconds = float(os.getenv("WHOIS_TIMEOUT_SECONDS", "8").strip())
    except ValueError:
        timeout_seconds = 8.0

    domain = hostname.split(":", 1)[0].strip().lower()
    if not domain:
        return None

    try:
        response = httpx.get(
            base_url,
            params={
                "apiKey": api_key,
                "domainName": domain,
                "outputFormat": "JSON",
            },
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        return None

    if not isinstance(payload, dict):
        return None

    created_dt = _extract_created_date(payload)
    if created_dt is None:
        return None
    return max((datetime.now(timezone.utc) - created_dt).days, 0)


def check_whois(hostname: str) -> dict[str, object]:
    """
    Compatibility adapter for teammate code expecting score/flags output.
    """
    age_days = get_domain_age_days(hostname)
    if age_days is None:
        return {"score": 0, "flags": []}

    flags: list[str] = []
    score = 0
    if age_days <= 30:
        score += 2
        flags.append("Domain recently registered (<=30 days)")
    return {"score": score, "flags": flags}
