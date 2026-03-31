"""Threat intelligence service adapter."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx

from app.core.logging import get_logger
from app.schemas.enums import Verdict
from app.schemas.threat_intel import ThreatIntelResult
from app.services.base import ServiceStub


def _flatten_indicators(value: Any) -> list[str]:
    """Normalize provider indicators into a flat string list."""

    if isinstance(value, list):
        normalized: list[str] = []
        for item in value:
            if isinstance(item, str) and item:
                normalized.append(item)
            elif isinstance(item, dict):
                name = item.get("name") or item.get("indicator") or item.get("value")
                if isinstance(name, str) and name:
                    normalized.append(name)
        return normalized
    if isinstance(value, str) and value:
        return [value]
    return []


def _normalize_verdict(value: Any, matched: bool) -> Verdict:
    """Normalize provider verdicts into shared enums."""

    if isinstance(value, str):
        normalized = value.strip().lower().replace("-", "_")
        mapping = {
            "clean": Verdict.SAFE,
            "safe": Verdict.SAFE,
            "benign": Verdict.SAFE,
            "unknown": Verdict.UNKNOWN,
            "suspicious": Verdict.SUSPICIOUS,
            "warning": Verdict.SUSPICIOUS,
            "malicious": Verdict.MALICIOUS,
            "dangerous": Verdict.MALICIOUS,
        }
        if normalized in mapping:
            return mapping[normalized]
    return Verdict.MALICIOUS if matched else Verdict.UNKNOWN


class ThreatIntelService(ServiceStub):
    """Aggregate third-party threat intelligence signals."""

    def __init__(self, context) -> None:
        super().__init__(context)
        self.logger = get_logger("qroulette.threat_intel")

    def _provider_name(self) -> str | None:
        """Derive a provider name from configuration."""

        base_url = self.context.settings.threat_intel_base_url
        return urlsplit(base_url).netloc or None

    def _fallback(
        self,
        url: str,
        error: str,
        raw_response: dict[str, Any] | None = None,
    ) -> ThreatIntelResult:
        """Return a consistent fallback result."""

        return ThreatIntelResult(
            url=url,
            provider=self._provider_name(),
            available=False,
            error=error,
            raw_response=raw_response or {},
        )

    async def lookup_indicators(self, url: str) -> ThreatIntelResult:
        """Return normalized threat intelligence data for a URL."""

        base_url = self.context.settings.threat_intel_base_url
        if not base_url:
            self.logger.warning(
                "Threat-intel lookup skipped because THREAT_INTEL_BASE_URL is missing."
            )
            return self._fallback(url, "Threat-intel provider is not configured.")

        api_key = self.context.settings.threat_intel_api_key
        if not api_key:
            self.logger.warning("Threat-intel lookup skipped because THREAT_INTEL_API_KEY is missing.")
            return self._fallback(url, "Threat-intel API key is not configured.")

        # WhoisXML Threat Intel API uses "ioc" (Indicator of Compromise) param.
        from urllib.parse import urlsplit as _urlsplit
        domain = _urlsplit(url).hostname or url

        try:
            response = await self.context.client.get(
                base_url,
                params={
                    "apiKey": api_key,
                    "ioc": domain,
                    "outputFormat": "JSON",
                },
                timeout=self.context.settings.threat_intel_timeout_seconds,
            )
            response.raise_for_status()
        except httpx.TimeoutException:
            self.logger.warning("Threat-intel lookup timed out for %s", url)
            return self._fallback(url, "Threat-intel lookup timed out.")
        except httpx.HTTPStatusError as exc:
            self.logger.error(
                "Threat-intel lookup failed for %s with status %s",
                url,
                exc.response.status_code,
            )
            return self._fallback(
                url,
                f"Threat-intel lookup failed with status {exc.response.status_code}.",
                {"body": exc.response.text[:500]},
            )
        except httpx.RequestError as exc:
            self.logger.error("Threat-intel transport error for %s: %s", url, exc)
            return self._fallback(url, "Threat-intel transport error.")

        try:
            payload = response.json()
        except ValueError:
            self.logger.error("Threat-intel provider returned invalid JSON for %s", url)
            return self._fallback(
                url,
                "Threat-intel provider returned an invalid JSON response.",
            )

        raw_response = payload if isinstance(payload, dict) else {"response": payload}

        # WhoisXML returns {total: N, results: [...]} where each result has threat types.
        results_list = raw_response.get("results") or []
        indicators = _flatten_indicators(
            results_list
            or raw_response.get("indicators")
            or raw_response.get("matches")
            or raw_response.get("threats")
        )
        reasons = _flatten_indicators(
            raw_response.get("reasons")
            or raw_response.get("details")
            or raw_response.get("signals")
        )
        total = raw_response.get("total", 0)
        matched_value = raw_response.get("matched")
        matched = bool(matched_value) if isinstance(matched_value, bool) else (bool(indicators) or (isinstance(total, int) and total > 0))
        confidence_value = raw_response.get("confidence")
        confidence = (
            float(confidence_value)
            if isinstance(confidence_value, (int, float)) and 0 <= confidence_value <= 1
            else None
        )
        verdict = _normalize_verdict(raw_response.get("verdict"), matched)

        return ThreatIntelResult(
            url=url,
            provider=raw_response.get("provider") if isinstance(raw_response.get("provider"), str) else self._provider_name(),
            matched=matched,
            verdict=verdict,
            confidence=confidence,
            indicator_count=len(indicators),
            indicators=indicators,
            reasons=reasons,
            raw_response=raw_response,
        )
