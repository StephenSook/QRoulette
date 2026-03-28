"""WHOIS service adapter."""

from __future__ import annotations

from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from app.core.logging import get_logger
from app.schemas.whois import WhoisResult
from app.services.base import ServiceStub


def _dig(data: dict[str, Any], *path: str) -> Any:
    """Safely walk nested provider payloads."""

    current: Any = data
    for segment in path:
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current


def _first_value(data: dict[str, Any], *paths: tuple[str, ...]) -> Any:
    """Return the first non-empty value from candidate paths."""

    for path in paths:
        value = _dig(data, *path)
        if value not in (None, "", []):
            return value
    return None


def _parse_datetime(value: Any) -> datetime | None:
    """Normalize provider dates into timezone-aware datetimes."""

    if isinstance(value, list):
        for item in value:
            parsed = _parse_datetime(item)
            if parsed is not None:
                return parsed
        return None

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=UTC)

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
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            continue

    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(normalized, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue

    try:
        parsed = parsedate_to_datetime(normalized)
    except (TypeError, ValueError, IndexError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _normalize_string_list(value: Any) -> list[str]:
    """Flatten provider-specific string collections."""

    if isinstance(value, str):
        return [value]

    if isinstance(value, list):
        return [item.strip() for item in value if isinstance(item, str) and item.strip()]

    if isinstance(value, dict):
        host_names = value.get("hostNames")
        if isinstance(host_names, list):
            return [
                item.strip() for item in host_names if isinstance(item, str) and item.strip()
            ]
    return []


class WhoisService(ServiceStub):
    """Retrieve WHOIS and domain registration metadata."""

    def __init__(self, context) -> None:
        super().__init__(context)
        self.logger = get_logger("qroulette.whois")

    def _fallback(
        self,
        domain: str,
        error: str,
        raw_response: dict[str, Any] | None = None,
    ) -> WhoisResult:
        """Return a consistent fallback object for orchestration."""

        return WhoisResult(
            domain=domain,
            available=False,
            found=False,
            error=error,
            raw_response=raw_response or {},
        )

    async def lookup_domain(self, domain: str) -> WhoisResult:
        """Return normalized WHOIS data for a domain."""

        api_key = self.context.settings.whois_xml_api_key
        if not api_key:
            self.logger.warning("WHOIS lookup skipped because WHOIS_XML_API_KEY is missing.")
            return self._fallback(domain, "WHOIS provider is not configured.")

        try:
            response = await self.context.client.get(
                self.context.settings.whois_base_url,
                params={
                    "apiKey": api_key,
                    "domainName": domain,
                    "outputFormat": "JSON",
                },
                timeout=self.context.settings.whois_timeout_seconds,
            )
            response.raise_for_status()
        except httpx.TimeoutException:
            self.logger.warning("WHOIS lookup timed out for %s", domain)
            return self._fallback(domain, "WHOIS lookup timed out.")
        except httpx.HTTPStatusError as exc:
            self.logger.error(
                "WHOIS lookup failed for %s with status %s",
                domain,
                exc.response.status_code,
            )
            return self._fallback(
                domain,
                f"WHOIS lookup failed with status {exc.response.status_code}.",
                {"body": exc.response.text[:500]},
            )
        except httpx.RequestError as exc:
            self.logger.error("WHOIS transport error for %s: %s", domain, exc)
            return self._fallback(domain, "WHOIS transport error.")

        try:
            payload = response.json()
        except ValueError:
            self.logger.error("WHOIS returned invalid JSON for %s", domain)
            return self._fallback(domain, "WHOIS returned an invalid JSON response.")

        raw_response = payload if isinstance(payload, dict) else {"response": payload}
        record = raw_response.get("WhoisRecord") or raw_response.get("whoisRecord") or {}

        # TODO: Adjust these paths if the chosen WHOIS vendor returns different keys.
        creation_date = _parse_datetime(
            _first_value(
                record,
                ("createdDateNormalized",),
                ("createdDate",),
                ("registryData", "createdDateNormalized"),
                ("registryData", "createdDate"),
                ("audit", "createdDate"),
            )
        )
        updated_date = _parse_datetime(
            _first_value(
                record,
                ("updatedDateNormalized",),
                ("updatedDate",),
                ("registryData", "updatedDateNormalized"),
                ("registryData", "updatedDate"),
            )
        )
        expiration_date = _parse_datetime(
            _first_value(
                record,
                ("expiresDateNormalized",),
                ("expiresDate",),
                ("registryData", "expiresDateNormalized"),
                ("registryData", "expiresDate"),
            )
        )

        now = datetime.now(tz=UTC)
        domain_age_days = None
        if creation_date is not None:
            domain_age_days = max(0, (now.date() - creation_date.date()).days)

        registrar = _first_value(
            record,
            ("registrarName",),
            ("registryData", "registrarName"),
            ("registrar",),
        )
        registrant_name = _first_value(
            record,
            ("registrant", "name"),
            ("registryData", "registrant", "name"),
        )
        nameservers = _normalize_string_list(
            _first_value(
                record,
                ("nameServers",),
                ("registryData", "nameServers"),
            )
        )
        statuses = _normalize_string_list(
            _first_value(
                record,
                ("status",),
                ("registryData", "status"),
            )
        )
        found = bool(record) and any(
            value is not None
            for value in (
                _first_value(record, ("domainName",), ("registryData", "domainName")),
                registrar,
                creation_date,
            )
        )

        return WhoisResult(
            domain=domain,
            found=found,
            registrar=registrar if isinstance(registrar, str) else None,
            registrant_name=registrant_name if isinstance(registrant_name, str) else None,
            creation_date=creation_date,
            updated_date=updated_date,
            expiration_date=expiration_date,
            domain_age_days=domain_age_days,
            nameservers=nameservers,
            statuses=statuses,
            raw_response=raw_response,
        )
