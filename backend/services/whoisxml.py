import os
import os
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()


def get_domain_age_days(hostname: str) -> int | None:
    """
    Return domain age in days when data is available.

    Current lightweight implementation supports a local override map for demo/testing:
    WHOIS_MOCK_AGES="paypal.com:9000,fake-paypal-demo.com:1"
    """
    mapping = os.getenv("WHOIS_MOCK_AGES", "").strip()
    if not mapping:
        return None

    ages: dict[str, int] = {}
    for item in mapping.split(","):
        if ":" not in item:
            continue
        host, days = item.split(":", 1)
        host = host.strip().lower()
        try:
            ages[host] = int(days.strip())
        except ValueError:
            continue

    host = hostname.lower().strip()
    if host in ages:
        return max(ages[host], 0)

    # If a creation date is provided, derive days from now.
    created_at = os.getenv("WHOIS_CREATED_AT")
    if created_at:
        try:
            created_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            return max((datetime.now(timezone.utc) - created_dt).days, 0)
        except ValueError:
            return None
    return None


def check_whois(hostname: str) -> dict[str, object]:
    """
    Compatibility adapter for teammate code expecting score/flags output.
    """
    age_days = get_domain_age_days(hostname)
    if age_days is None:
        return {"score": 0, "flags": []}

    flags: list[str] = []
    score = 0
    if age_days <= 30:
        score += 2
        flags.append("Domain recently registered (<=30 days)")
    return {"score": score, "flags": flags}
