import os
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v5/urls:search"


def check_safe_browsing(url: str) -> dict[str, Any]:
    """Return Safe Browsing lookup result using Google v5 direct URL search."""
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or os.getenv("GOOGLE_SAFE_API_KEY")
    if not api_key:
        return {
            "matched": False,
            "threat_types": [],
            "error": "GOOGLE_SAFE_BROWSING_API_KEY is missing.",
        }

    try:
        response = httpx.get(
            SAFE_BROWSING_URL,
            params={"key": api_key, "urls[]": url},
            timeout=5.0,
        )
        response.raise_for_status()
        payload = response.json()
    except httpx.HTTPError as exc:
        return {
            "matched": False,
            "threat_types": [],
            "error": f"Safe Browsing request failed: {exc}",
        }

    threats = payload.get("threats", []) or []
    threat_types = sorted(
        {
            threat_type
            for threat in threats
            for threat_type in threat.get("threatTypes", [])
            if isinstance(threat_type, str)
        }
    )
    return {
        "matched": bool(threats),
        "threat_types": threat_types,
        "error": None,
    }