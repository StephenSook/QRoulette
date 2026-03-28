"""Redirect chain analysis service."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx

from app.core.logging import get_logger
from app.schemas.redirects import RedirectHop, RedirectsResult
from app.services.base import ServiceStub


def _classify_redirects(hop_count: int) -> str:
    """Translate hop count into a redirect risk band."""

    if hop_count >= 4:
        return "high_risk"
    if hop_count >= 3:
        return "suspicious"
    return "normal"


class RedirectsService(ServiceStub):
    """Inspect redirect chains for destination URLs."""

    def __init__(self, context) -> None:
        super().__init__(context)
        self.logger = get_logger("qroulette.redirects")

    def _fallback(
        self,
        url: str,
        error: str,
        raw_response: dict[str, Any] | None = None,
    ) -> RedirectsResult:
        """Return a consistent fallback redirect result."""

        return RedirectsResult(
            input_url=url,
            final_url=url,
            available=False,
            error=error,
            raw_response=raw_response or {},
        )

    async def inspect_chain(self, url: str) -> RedirectsResult:
        """Return full redirect chain metadata for a URL."""

        try:
            response = await self.context.client.get(
                url,
                timeout=self.context.settings.redirects_timeout_seconds,
                follow_redirects=True,
            )
        except httpx.TimeoutException:
            self.logger.warning("Redirect inspection timed out for %s", url)
            return self._fallback(url, "Redirect inspection timed out.")
        except httpx.RequestError as exc:
            self.logger.error("Redirect inspection transport error for %s: %s", url, exc)
            return self._fallback(url, "Redirect inspection transport error.")

        hops: list[RedirectHop] = []
        has_cross_domain_redirect = False
        history = list(response.history)

        for index, hop_response in enumerate(history):
            current_url = str(hop_response.request.url)
            next_response = history[index + 1] if index + 1 < len(history) else response
            next_url = str(next_response.request.url)
            current_host = urlsplit(current_url).hostname
            next_host = urlsplit(next_url).hostname
            is_cross_domain = bool(current_host and next_host and current_host != next_host)
            has_cross_domain_redirect = has_cross_domain_redirect or is_cross_domain
            hops.append(
                RedirectHop(
                    url=current_url,
                    status_code=hop_response.status_code,
                    location=hop_response.headers.get("location"),
                    next_url=next_url,
                    hostname=current_host,
                    is_cross_domain=is_cross_domain,
                )
            )

        raw_response = {
            "history": [
                {
                    "url": str(item.request.url),
                    "status_code": item.status_code,
                    "location": item.headers.get("location"),
                }
                for item in history
            ],
            "final": {
                "url": str(response.url),
                "status_code": response.status_code,
            },
        }
        hop_count = len(hops)

        return RedirectsResult(
            input_url=url,
            final_url=str(response.url),
            hop_count=hop_count,
            classification=_classify_redirects(hop_count),
            has_cross_domain_redirect=has_cross_domain_redirect,
            hops=hops,
            raw_response=raw_response,
        )
