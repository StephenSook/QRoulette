import os

import httpx
from dotenv import load_dotenv

load_dotenv()


def _fallback_summary(url: str, risk_level: str, reasons: list[str]) -> str:
    if not reasons:
        return f"{url} appears {risk_level} with no specific indicators."
    top_reasons = "; ".join(reasons[:3])
    return f"{url} is classified as {risk_level}. Key indicators: {top_reasons}."


def summarize_risk(url: str, risk_level: str, reasons: list[str]) -> str:
    """
    Generate an AI summary using Gemini when configured, with deterministic fallback.
    """
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return _fallback_summary(url, risk_level, reasons)

    base_url = os.getenv(
        "GEMINI_BASE_URL",
        "https://generativelanguage.googleapis.com/v1beta",
    ).rstrip("/")
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()
    try:
        timeout_seconds = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "10").strip())
    except ValueError:
        timeout_seconds = 10.0

    reason_text = "; ".join(reasons[:6]) if reasons else "No explicit risk signals."
    prompt = (
        "You are a URL security analyst. Provide one concise sentence (max 35 words) "
        "explaining the risk classification.\n"
        f"URL: {url}\n"
        f"Risk level: {risk_level}\n"
        f"Signals: {reason_text}\n"
        "Do not use markdown."
    )
    endpoint = f"{base_url}/models/{model}:generateContent"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 180,
            # Reduce hidden reasoning tokens so the visible summary is not cut off.
            "thinkingConfig": {"thinkingBudget": 0},
        },
    }

    try:
        response = httpx.post(
            endpoint,
            params={"key": api_key},
            json=payload,
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
        candidates = data.get("candidates", []) if isinstance(data, dict) else []
        if candidates:
            candidate = candidates[0] if isinstance(candidates[0], dict) else {}
            finish_reason = str(candidate.get("finishReason", "")).upper()
            content = candidate.get("content", {})
            parts = content.get("parts", []) if isinstance(content, dict) else []
            text_parts = [p.get("text", "").strip() for p in parts if isinstance(p, dict)]
            generated = " ".join(part for part in text_parts if part).strip()
            if (
                generated
                and len(generated) >= 24
                and finish_reason not in {"MAX_TOKENS", "SAFETY", "RECITATION"}
            ):
                return generated
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return _fallback_summary(url, risk_level, reasons)

    return _fallback_summary(url, risk_level, reasons)
