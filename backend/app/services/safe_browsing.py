"""Google Safe Browsing v5 direct-lookup service."""

from __future__ import annotations

from typing import Any

import httpx

from app.core.logging import get_logger
from app.schemas.safe_browsing import SafeBrowsingResult
from app.services.base import ServiceStub

SAFE_BROWSING_SEARCH_PATH = "/v5/urls:search"


class SafeBrowsingService(ServiceStub):
    """Query Google Safe Browsing for malicious URL signals."""

    def __init__(self, context) -> None:
        super().__init__(context)
        self.logger = get_logger("qroulette.safe_browsing")

    async def check_url(self, url: str) -> SafeBrowsingResult:
        """Return the Safe Browsing verdict for a URL using v5 direct lookup."""

        api_key = self.context.settings.google_safe_browsing_api_key
        if not api_key:
            self.logger.error("Google Safe Browsing API key is not configured.")
            raise ValueError("GOOGLE_SAFE_BROWSING_API_KEY is required.")

        request_url = (
            f"{self.context.settings.safe_browsing_base_url.rstrip('/')}"
            f"{SAFE_BROWSING_SEARCH_PATH}"
        )
        params = [
            ("key", api_key),
            ("urls[]", url),
        ]

        self.logger.info("Checking URL with Google Safe Browsing v5: %s", url)

        try:
            response = await self.context.client.get(
                request_url,
                params=params,
                timeout=self.context.settings.safe_browsing_timeout_seconds,
            )
            response.raise_for_status()
        except httpx.TimeoutException as exc:
            self.logger.warning("Safe Browsing request timed out for %s", url)
            raise RuntimeError("Safe Browsing request timed out.") from exc
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            body_preview = exc.response.text[:500]
            self.logger.error(
                "Safe Browsing v5 returned HTTP %s for %s: %s",
                status_code,
                url,
                body_preview,
            )
            raise RuntimeError(
                f"Safe Browsing request failed with status {status_code}."
            ) from exc
        except httpx.RequestError as exc:
            self.logger.error("Safe Browsing transport error for %s: %s", url, exc)
            raise RuntimeError("Safe Browsing transport error.") from exc

        try:
            payload: dict[str, Any] = response.json()
        except ValueError as exc:
            self.logger.error("Safe Browsing returned invalid JSON for %s", url)
            raise RuntimeError("Safe Browsing returned an invalid JSON response.") from exc
        threats = payload.get("threats", []) or []

        threat_types = sorted(
            {
                threat_type
                for threat in threats
                for threat_type in threat.get("threatTypes", [])
                if isinstance(threat_type, str)
            }
        )

        result = SafeBrowsingResult(
            matched=bool(threats),
            threat_types=threat_types,
            raw_response=payload,
        )

        self.logger.info(
            "Safe Browsing result for %s: matched=%s threat_types=%s",
            url,
            result.matched,
            ",".join(result.threat_types) if result.threat_types else "none",
        )
        return result
