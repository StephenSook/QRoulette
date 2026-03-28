"""Gemini integration service."""

from __future__ import annotations

from typing import Any

import httpx

from app.core.logging import get_logger
from app.schemas.domain import ScoreBreakdownItem
from app.schemas.gemini import GeminiExplanationResult
from app.services.base import ServiceStub


class GeminiService(ServiceStub):
    """Use Gemini for higher-level risk reasoning."""

    def __init__(self, context) -> None:
        super().__init__(context)
        self.logger = get_logger("qroulette.gemini")

    def _fallback(
        self,
        error: str,
        raw_response: dict[str, Any] | None = None,
    ) -> GeminiExplanationResult:
        """Return a consistent best-effort explanation result."""

        return GeminiExplanationResult(
            available=False,
            model=self.context.settings.gemini_model,
            error=error,
            raw_response=raw_response or {},
        )

    async def review_url(
        self,
        *,
        url: str,
        verdict: str,
        score: int,
        score_breakdown: list[ScoreBreakdownItem],
    ) -> GeminiExplanationResult:
        """Return a short Gemini-assisted explanation for a completed scan."""

        api_key = self.context.settings.gemini_api_key
        if not api_key:
            self.logger.info("Gemini explanation skipped because GEMINI_API_KEY is missing.")
            return self._fallback("Gemini is not configured.")

        prompt_lines = [
            "You are generating a short QR security explanation for an end user.",
            "Respond with 1-2 concise sentences and no bullet points.",
            f"URL: {url}",
            f"Verdict: {verdict}",
            f"Risk score: {score}/100",
        ]
        for item in score_breakdown[:4]:
            prompt_lines.append(f"- {item.label}: {item.rationale}")

        request_url = (
            f"{self.context.settings.gemini_base_url.rstrip('/')}/models/"
            f"{self.context.settings.gemini_model}:generateContent"
        )
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": "\n".join(prompt_lines),
                        }
                    ]
                }
            ]
        }

        try:
            response = await self.context.client.post(
                request_url,
                headers={
                    "x-goog-api-key": api_key,
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=self.context.settings.gemini_timeout_seconds,
            )
            response.raise_for_status()
        except httpx.TimeoutException:
            self.logger.warning("Gemini explanation request timed out for %s", url)
            return self._fallback("Gemini explanation timed out.")
        except httpx.HTTPStatusError as exc:
            self.logger.error(
                "Gemini explanation failed for %s with status %s",
                url,
                exc.response.status_code,
            )
            return self._fallback(
                f"Gemini explanation failed with status {exc.response.status_code}.",
                {"body": exc.response.text[:500]},
            )
        except httpx.RequestError as exc:
            self.logger.error("Gemini transport error for %s: %s", url, exc)
            return self._fallback("Gemini transport error.")

        try:
            body = response.json()
        except ValueError:
            self.logger.error("Gemini returned invalid JSON for %s", url)
            return self._fallback("Gemini returned an invalid JSON response.")

        raw_response = body if isinstance(body, dict) else {"response": body}
        candidates = raw_response.get("candidates") or []
        text: str | None = None
        if candidates and isinstance(candidates[0], dict):
            content = candidates[0].get("content") or {}
            parts = content.get("parts") or []
            for part in parts:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    text = part["text"].strip()
                    if text:
                        break

        if not text:
            return self._fallback(
                "Gemini returned no text explanation.",
                raw_response,
            )

        return GeminiExplanationResult(
            model=self.context.settings.gemini_model,
            summary=text,
            raw_response=raw_response,
        )
