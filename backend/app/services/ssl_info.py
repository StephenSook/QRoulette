"""SSL/TLS inspection service adapter."""

from __future__ import annotations

from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.core.logging import get_logger
from app.schemas.enums import Verdict
from app.schemas.ssl_info import SSLInfoResult
from app.services.base import ServiceStub


def _parse_datetime(value: Any) -> datetime | None:
    """Normalize provider date fields into timezone-aware datetimes."""

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=UTC)
    if not isinstance(value, str) or not value.strip():
        return None

    normalized = value.strip()
    candidates = [normalized]
    if normalized.endswith("Z"):
        candidates.append(normalized[:-1] + "+00:00")

    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            continue

    try:
        parsed = parsedate_to_datetime(normalized)
    except (TypeError, ValueError, IndexError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class SSLInfoService(ServiceStub):
    """Inspect TLS certificate details for remote hosts."""

    def __init__(self, context) -> None:
        super().__init__(context)
        self.logger = get_logger("qroulette.ssl_info")

    def _provider_name(self) -> str | None:
        """Derive a provider name from configuration."""

        return urlsplit(self.context.settings.ssl_info_base_url).netloc or None

    def _fallback(
        self,
        host: str,
        error: str,
        raw_response: dict[str, Any] | None = None,
    ) -> SSLInfoResult:
        """Return a consistent fallback inspection result."""

        return SSLInfoResult(
            host=host,
            provider=self._provider_name(),
            available=False,
            error=error,
            raw_response=raw_response or {},
        )

    async def inspect_host(self, host: str) -> SSLInfoResult:
        """Return normalized SSL metadata for a host."""

        base_url = self.context.settings.ssl_info_base_url
        if not base_url:
            self.logger.warning("SSL inspection skipped because SSL_INFO_BASE_URL is missing.")
            return self._fallback(host, "SSL-info provider is not configured.")

        headers: dict[str, str] = {}
        if self.context.settings.ssl_info_api_key:
            # TODO: Update auth/header handling when the SSL vendor contract is finalized.
            headers["Authorization"] = f"Bearer {self.context.settings.ssl_info_api_key}"

        try:
            response = await self.context.client.get(
                base_url,
                params={"host": host},
                headers=headers or None,
                timeout=self.context.settings.ssl_info_timeout_seconds,
            )
            response.raise_for_status()
        except httpx.TimeoutException:
            self.logger.warning("SSL inspection timed out for %s", host)
            return self._fallback(host, "SSL inspection timed out.")
        except httpx.HTTPStatusError as exc:
            self.logger.error(
                "SSL inspection failed for %s with status %s",
                host,
                exc.response.status_code,
            )
            return self._fallback(
                host,
                f"SSL inspection failed with status {exc.response.status_code}.",
                {"body": exc.response.text[:500]},
            )
        except httpx.RequestError as exc:
            self.logger.error("SSL inspection transport error for %s: %s", host, exc)
            return self._fallback(host, "SSL inspection transport error.")

        try:
            payload = response.json()
        except ValueError:
            self.logger.error("SSL provider returned invalid JSON for %s", host)
            return self._fallback(host, "SSL provider returned an invalid JSON response.")

        raw_response = payload if isinstance(payload, dict) else {"response": payload}
        certificate = (
            raw_response.get("certificate")
            or raw_response.get("cert")
            or raw_response.get("result")
            or raw_response
        )
        if not isinstance(certificate, dict):
            certificate = {}

        # TODO: Tighten these fields to the chosen SSL vendor's schema.
        valid_from = _parse_datetime(
            certificate.get("valid_from")
            or certificate.get("notBefore")
            or certificate.get("issued_at")
        )
        valid_to = _parse_datetime(
            certificate.get("valid_to")
            or certificate.get("notAfter")
            or certificate.get("expires_at")
        )
        issuer = certificate.get("issuer")
        subject = certificate.get("subject")
        san_entries = certificate.get("subjectAltNames") or certificate.get("sans")
        san_count = len(san_entries) if isinstance(san_entries, list) else None
        has_tls = bool(certificate) and raw_response.get("has_tls", True) is not False
        self_signed_value = certificate.get("self_signed")
        self_signed = (
            bool(self_signed_value)
            if isinstance(self_signed_value, bool)
            else isinstance(issuer, str) and isinstance(subject, str) and issuer == subject
        )
        is_expired = valid_to < datetime.now(tz=UTC) if valid_to is not None else None
        days_until_expiry = None
        if valid_to is not None:
            days_until_expiry = (valid_to.date() - datetime.now(tz=UTC).date()).days

        reasons: list[str] = []
        verdict = Verdict.UNKNOWN
        if not has_tls:
            reasons.append("TLS certificate data was not available.")
            verdict = Verdict.SUSPICIOUS
        elif is_expired:
            reasons.append("TLS certificate appears to be expired.")
            verdict = Verdict.SUSPICIOUS
        elif self_signed:
            reasons.append("TLS certificate appears to be self-signed.")
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.SAFE

        return SSLInfoResult(
            host=host,
            provider=raw_response.get("provider") if isinstance(raw_response.get("provider"), str) else self._provider_name(),
            has_tls=has_tls,
            issuer=issuer if isinstance(issuer, str) else None,
            subject=subject if isinstance(subject, str) else None,
            valid_from=valid_from,
            valid_to=valid_to,
            days_until_expiry=days_until_expiry,
            san_count=san_count,
            is_expired=is_expired,
            self_signed=self_signed,
            verdict=verdict,
            reasons=reasons,
            raw_response=raw_response,
        )
