# Google safe browsing API
# backend/services/safe_browsing.py

import os
import requests
from dotenv import load_dotenv

load_dotenv()
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_API_KEY")

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v5/threatMatches:find"

def check_safe_browsing(url: str) -> dict:
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        raise ValueError("Google Safe Browsing API key not found")
    try:
        response = requests.get(
            SAFE_BROWSING_URL,
            params={"key": GOOGLE_SAFE_BROWSING_API_KEY, "urls": url},
            timeout = 5
        )
        response.raise_for_status()
        data = response.json()

        if "threats" in data:
            flags = [f"Safe Browsing: {t['threatType']} detected" for t in data["threats"]]
            return {"score": 5, "flags": flags}
        else:
            return {"score": 0, "flags": []}
    except requests.RequestException as e:
        return {"score": 1, "flags": [f"Safe Browsing API error: {e}"]}