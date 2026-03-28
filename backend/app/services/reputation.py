"""Domain reputation service adapter."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx

from app.core.logging import get_logger
from app.schemas.enums import Verdict
from app.schemas.reputation import ReputationResult
from app.services.base import ServiceStub


def _as_list(value: Any) -> list[str]:
    """Normalize free-form string collections."""

    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str) and item]
    return []


def _normalize_score(value: Any) -> float | None:
    """Normalize provider scores into a 0-100 range."""

    if not isinstance(value, (int, float)):
        return None
    if 0 <= value <= 1:
        return round(float(value) * 100, 2)
    if 0 <= value <= 100:
        return round(float(value), 2)
    return None


def _normalize_verdict(value: Any, score: float | None) -> Verdict:
    """Normalize provider-specific verdict values."""

    if isinstance(value, str):
        normalized = value.strip().lower().replace("-", "_")
        mapping = {
            "clean": Verdict.SAFE,
            "safe": Verdict.SAFE,
            "benign": Verdict.SAFE,
            "low": Verdict.SAFE,
            "unknown": Verdict.UNKNOWN,
            "unrated": Verdict.UNKNOWN,
            "medium": Verdict.SUSPICIOUS,
            "suspicious": Verdict.SUSPICIOUS,
            "warning": Verdict.SUSPICIOUS,
            "high": Verdict.MALICIOUS,
            "bad": Verdict.MALICIOUS,
            "malicious": Verdict.MALICIOUS,
            "dangerous": Verdict.MALICIOUS,
        }
        if normalized in mapping:
            return mapping[normalized]

    if score is None:
        return Verdict.UNKNOWN
    if score >= 75:
        return Verdict.MALICIOUS
    if score >= 40:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE


class ReputationService(ServiceStub):
    """Evaluate URL and domain reputation signals."""

    def __init__(self, context) -> None:
        super().__init__(context)
        self.logger = get_logger("qroulette.reputation")

    def _provider_name(self) -> str | None:
        """Derive a human-readable provider identifier from configuration."""

        base_url = self.context.settings.reputation_base_url
        return urlsplit(base_url).netloc or None

    def _fallback(
        self,
        url: str,
        error: str,
        raw_response: dict[str, Any] | None = None,
    ) -> ReputationResult:
        """Return an orchestration-friendly fallback result."""

        return ReputationResult(
            url=url,
            provider=self._provider_name(),
            available=False,
            error=error,
            raw_response=raw_response or {},
        )

    async def score_url(self, url: str) -> ReputationResult:
        """Return normalized reputation data for a URL."""

        base_url = self.context.settings.reputation_base_url
        if not base_url:
            self.logger.warning("Reputation lookup skipped because REPUTATION_BASE_URL is missing.")
            return self._fallback(url, "Reputation provider is not configured.")

        headers: dict[str, str] = {}
        if self.context.settings.reputation_api_key:
            # TODO: Update auth/header shape when the concrete reputation vendor is chosen.
            headers["Authorization"] = (
                f"Bearer {self.context.settings.reputation_api_key}"
            )

        try:
            response = await self.context.client.get(
                base_url,
                params={"url": url},
                headers=headers or None,
                timeout=self.context.settings.reputation_timeout_seconds,
            )
            response.raise_for_status()
        except httpx.TimeoutException:
            self.logger.warning("Reputation lookup timed out for %s", url)
            return self._fallback(url, "Reputation lookup timed out.")
        except httpx.HTTPStatusError as exc:
            self.logger.error(
                "Reputation lookup failed for %s with status %s",
                url,
                exc.response.status_code,
            )
            return self._fallback(
                url,
                f"Reputation lookup failed with status {exc.response.status_code}.",
                {"body": exc.response.text[:500]},
            )
        except httpx.RequestError as exc:
            self.logger.error("Reputation transport error for %s: %s", url, exc)
            return self._fallback(url, "Reputation transport error.")

        try:
            payload = response.json()
        except ValueError:
            self.logger.error("Reputation provider returned invalid JSON for %s", url)
            return self._fallback(url, "Reputation provider returned an invalid JSON response.")

        raw_response = payload if isinstance(payload, dict) else {"response": payload}

        # TODO: Narrow these fields to the real provider contract once selected.
        score = _normalize_score(
            raw_response.get("score")
            or raw_response.get("reputationScore")
            or raw_response.get("risk_score")
        )
        confidence_value = raw_response.get("confidence")
        confidence = (
            float(confidence_value)
            if isinstance(confidence_value, (int, float)) and 0 <= confidence_value <= 1
            else None
        )
        categories = _as_list(raw_response.get("categories") or raw_response.get("tags"))
        reasons = _as_list(
            raw_response.get("reasons")
            or raw_response.get("details")
            or raw_response.get("signals")
        )
        verdict = _normalize_verdict(
            raw_response.get("verdict") or raw_response.get("classification"),
            score,
        )

        return ReputationResult(
            url=url,
            provider=raw_response.get("provider") if isinstance(raw_response.get("provider"), str) else self._provider_name(),
            score=score,
            verdict=verdict,
            confidence=confidence,
            categories=categories,
            reasons=reasons,
            raw_response=raw_response,
        )
