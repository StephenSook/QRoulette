import os
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()

SAFE_BROWSING_V4_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_safe_browsing(url: str) -> dict[str, Any]:
    """Return Safe Browsing lookup result using Google threat match API."""
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or os.getenv("GOOGLE_SAFE_API_KEY")
    if not api_key:
        return {
            "matched": False,
            "threat_types": [],
            "error": "GOOGLE_SAFE_BROWSING_API_KEY is missing.",
        }

    client_id = os.getenv("SAFE_BROWSING_CLIENT_ID", "qroulette")
    client_version = os.getenv("SAFE_BROWSING_CLIENT_VERSION", "1.0.0")
    body = {
        "client": {"clientId": client_id, "clientVersion": client_version},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = httpx.post(
            SAFE_BROWSING_V4_URL,
            params={"key": api_key},
            json=body,
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

    threats = payload.get("matches", []) or []
    threat_types = sorted(
        {
            str(threat_type)
            for threat in threats
            for threat_type in [threat.get("threatType")]
            if isinstance(threat_type, str) and threat_type
        }
    )
    return {
        "matched": bool(threats),
        "threat_types": threat_types,
        "error": None,
    }