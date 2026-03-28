# WhoisXML checkers with API calls

# backend/services/whoisxml.py

import os
import requests
from urllib.parse import urlparse
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load API key
load_dotenv()
WHOISXML_API_KEY = os.getenv("WHOISXML_API_KEY")
WHOISXML_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

def check_whois(url: str) -> dict:
    """
    Query WHOISXML API for domain info.

    Returns:
    {
        "score": int,
        "flags": list[str]
    }
    """
    if not WHOISXML_API_KEY:
        raise ValueError("WHOISXML API key not set in .env")

    parsed = urlparse(url)
    domain = parsed.netloc

    params = {
        "apiKey": WHOISXML_API_KEY,
        "domainName": domain,
        "outputFormat": "JSON"
    }

    try:
        response = requests.get(WHOISXML_URL, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()

        score = 0
        flags = []

        registry = data.get("WhoisRecord", {})
        registrant = registry.get("registrant", {})
        registry_data = registry.get("registryData", {})

        # Check domain age
        creation_date_str = registry_data.get("registryData", {}).get("createdDate")
        if creation_date_str:
            try:
                creation_date = datetime.strptime(creation_date_str[:10], "%Y-%m-%d")
                if datetime.utcnow() - creation_date <= timedelta(days=30):
                    score += 2
                    flags.append("Domain recently registered (≤30 days)")
            except:
                pass

        # Check registrant privacy
        if registrant.get("name") in [None, "", "REDACTED FOR PRIVACY"]:
            score += 1
            flags.append("Registrant information hidden/private")

        # Check registrar abuse patterns (optional, example)
        registrar = registry_data.get("registryData", {}).get("registrarName", "")
        if registrar and registrar.lower() in ["some-abused-registrar.com"]:
            score += 1
            flags.append(f"Registrar {registrar} known for abuse")

        return {"score": score, "flags": flags}

    except requests.RequestException as e:
        return {"score": 1, "flags": [f"WHOIS API error: {e}"]}