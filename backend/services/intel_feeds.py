import os
from typing import Any
from urllib.parse import urlsplit

import httpx
from dotenv import load_dotenv

load_dotenv()


def _request_with_fallback(
    base_url: str,
    timeout_seconds: float,
    params: dict[str, Any],
    api_key: str = "",
) -> dict[str, Any] | None:
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
    try:
        response = httpx.get(
            base_url,
            params=params,
            headers=headers,
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, dict) else {"response": payload}
    except (httpx.HTTPError, ValueError):
        return None


def get_reputation_signal(url: str) -> dict[str, Any]:
    base_url = os.getenv("REPUTATION_BASE_URL", "").strip()
    if not base_url:
        return {"available": False, "risky": False, "score": None, "reasons": []}

    api_key = os.getenv("REPUTATION_API_KEY", "").strip()
    try:
        timeout_seconds = float(os.getenv("REPUTATION_TIMEOUT_SECONDS", "8").strip())
    except ValueError:
        timeout_seconds = 8.0

    payload = _request_with_fallback(
        base_url=base_url,
        timeout_seconds=timeout_seconds,
        params={"url": url},
        api_key=api_key,
    )
    if payload is None:
        return {"available": False, "risky": False, "score": None, "reasons": []}

    score_value = (
        payload.get("score")
        or payload.get("reputationScore")
        or payload.get("risk_score")
    )
    score: float | None = None
    if isinstance(score_value, (int, float)):
        if 0 <= score_value <= 1:
            score = float(score_value) * 100
        elif 0 <= score_value <= 100:
            score = float(score_value)

    verdict = str(payload.get("verdict") or payload.get("classification") or "").lower()
    risky = bool((score is not None and score >= 70) or verdict in {"malicious", "dangerous", "high"})
    reasons_raw = payload.get("reasons") or payload.get("signals") or payload.get("details") or []
    reasons = [item for item in reasons_raw if isinstance(item, str)] if isinstance(reasons_raw, list) else []
    return {
        "available": True,
        "risky": risky,
        "score": round(score, 2) if score is not None else None,
        "reasons": reasons[:3],
    }


def get_threat_intel_signal(url: str) -> dict[str, Any]:
    base_url = os.getenv("THREAT_INTEL_BASE_URL", "").strip()
    if not base_url:
        return {"available": False, "matched": False, "indicator_count": 0, "reasons": []}

    api_key = os.getenv("THREAT_INTEL_API_KEY", "").strip()
    try:
        timeout_seconds = float(os.getenv("THREAT_INTEL_TIMEOUT_SECONDS", "8").strip())
    except ValueError:
        timeout_seconds = 8.0

    payload = _request_with_fallback(
        base_url=base_url,
        timeout_seconds=timeout_seconds,
        params={"url": url},
        api_key=api_key,
    )
    if payload is None:
        return {"available": False, "matched": False, "indicator_count": 0, "reasons": []}

    indicators_raw = payload.get("indicators") or payload.get("matches") or payload.get("threats") or []
    indicator_count = len(indicators_raw) if isinstance(indicators_raw, list) else 0
    matched = payload.get("matched")
    if isinstance(matched, bool):
        is_matched = matched
    else:
        is_matched = indicator_count > 0
    reasons_raw = payload.get("reasons") or payload.get("details") or payload.get("signals") or []
    reasons = [item for item in reasons_raw if isinstance(item, str)] if isinstance(reasons_raw, list) else []
    return {
        "available": True,
        "matched": is_matched,
        "indicator_count": indicator_count,
        "reasons": reasons[:3],
    }


def get_ssl_signal(host: str) -> dict[str, Any]:
    base_url = os.getenv("SSL_INFO_BASE_URL", "").strip()
    if not base_url:
        return {"available": False, "has_tls": None, "is_expired": None, "self_signed": None}

    api_key = os.getenv("SSL_INFO_API_KEY", "").strip()
    try:
        timeout_seconds = float(os.getenv("SSL_INFO_TIMEOUT_SECONDS", "8").strip())
    except ValueError:
        timeout_seconds = 8.0

    hostname = (host or "").strip().lower()
    if not hostname:
        return {"available": False, "has_tls": None, "is_expired": None, "self_signed": None}

    payload = _request_with_fallback(
        base_url=base_url,
        timeout_seconds=timeout_seconds,
        params={"host": hostname},
        api_key=api_key,
    )
    if payload is None:
        return {"available": False, "has_tls": None, "is_expired": None, "self_signed": None}

    cert = payload.get("certificate") or payload.get("cert") or payload.get("result") or payload
    cert = cert if isinstance(cert, dict) else {}
    has_tls = payload.get("has_tls")
    if not isinstance(has_tls, bool):
        has_tls = bool(cert)
    is_expired = payload.get("is_expired")
    if not isinstance(is_expired, bool):
        is_expired = None
    self_signed = cert.get("self_signed")
    if not isinstance(self_signed, bool):
        issuer = cert.get("issuer")
        subject = cert.get("subject")
        self_signed = isinstance(issuer, str) and isinstance(subject, str) and issuer == subject

    return {
        "available": True,
        "has_tls": has_tls,
        "is_expired": is_expired,
        "self_signed": self_signed,
        "provider": urlsplit(base_url).netloc or None,
    }
