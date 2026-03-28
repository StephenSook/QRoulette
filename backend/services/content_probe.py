import re
from urllib.parse import urlparse

import httpx

URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
DOMAIN_PATTERN = re.compile(r"\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\b")


def probe_embedded_destination(url: str) -> str | None:
    """
    For short-link/preview pages that do not issue HTTP redirects, inspect HTML/text
    for embedded destination URLs/domains and return a candidate absolute URL.
    """
    try:
        try:
            response = httpx.get(url, follow_redirects=True, timeout=8.0)
        except httpx.ConnectError as exc:
            if "CERTIFICATE_VERIFY_FAILED" in str(exc).upper():
                response = httpx.get(url, follow_redirects=True, timeout=8.0, verify=False)
            else:
                raise
        response.raise_for_status()
        body = response.text[:20000]
    except httpx.HTTPError:
        return None

    source_host = (urlparse(str(response.url)).hostname or "").lower()

    for match in URL_PATTERN.findall(body):
        host = (urlparse(match).hostname or "").lower()
        if host and host != source_host:
            return match

    for token in DOMAIN_PATTERN.findall(body):
        host = token.lower().strip(".")
        if host and host != source_host and "." in host:
            return f"https://{host}"

    return None
