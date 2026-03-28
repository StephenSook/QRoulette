from urllib.parse import urlparse

BRAND_KEYWORDS = (
    "paypal",
    "chase",
    "bankofamerica",
    "venmo",
    "cashapp",
    "stripe",
    "zelle",
)

SUSPICIOUS_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
}


def _normalized_brand_like(text: str) -> str:
    out = text.lower()
    for src, dest in SUSPICIOUS_SUBSTITUTIONS.items():
        out = out.replace(src, dest)
    return out


def detect_typosquatting(target: str) -> bool:
    """Heuristic typo/brand impersonation detector for hostnames."""
    host = target.lower().strip()
    if "://" in host:
        host = (urlparse(host).netloc or "").lower()
    host = host.split(":")[0]

    normalized = _normalized_brand_like(host)
    return any(brand in normalized and brand not in host for brand in BRAND_KEYWORDS)
