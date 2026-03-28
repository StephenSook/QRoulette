import os
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv

load_dotenv()

SUSPICIOUS_TLDS = {"ru", "cn", "tk", "ml", "ga", "cf", "life"}
URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "qrco.de",
    "goo.gl",
    "ow.ly",
    "is.gd",
}


def _extract_domain(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""

def get_redirect_chain(url: str, max_hops: int = 6) -> dict:
    """
    Analyze a URL's redirect chain for phishing/quishing indicators.

    Returns:
    {
      "score": int,
      "flags": list[str],
      "chain": list[str],
      "domains": list[str],
      "final_url": str,
      "hops": int,
    }
    """
    try:
        try:
            timeout_seconds = float(os.getenv("REDIRECTS_TIMEOUT_SECONDS", "8").strip())
        except ValueError:
            timeout_seconds = 8.0
        tls_probe_degraded = False
        try:
            response = httpx.get(url, follow_redirects=True, timeout=timeout_seconds)
        except httpx.ConnectError as exc:
            # Some short-link/CDN setups can fail trust-chain verification in local
            # environments; retry without verification for read-only inspection.
            if "CERTIFICATE_VERIFY_FAILED" in str(exc).upper():
                response = httpx.get(
                    url,
                    follow_redirects=True,
                    timeout=timeout_seconds,
                    verify=False,
                )
                tls_probe_degraded = True
            else:
                raise
        chain = [str(resp.url) for resp in response.history]
        chain.append(str(response.url))
        final_url = chain[-1] if chain else url

        score = 0
        flags = []

        hops = len(chain) - 1
        domains = [_extract_domain(u) for u in chain]
        unique_domains = [d for d in dict.fromkeys(domains) if d]

        cross_domain = False
        if hops > 0:
            start_host = urlparse(chain[0]).hostname
            end_host = urlparse(chain[-1]).hostname
            cross_domain = bool(start_host and end_host and start_host != end_host)
        if cross_domain:
            flags.append("Redirect chain crosses domains")
            score += 1
        if tls_probe_degraded:
            flags.append("Redirect probe used relaxed TLS verification")

        # --- 1. Redirect Depth ---
        if hops <= 2:
            pass  # normal
        elif 3 <= hops <= 5:
            score += 2
            flags.append(f"{hops} redirects — unusual behavior")
        elif hops > 5:
            score += 3
            flags.append(f"{hops} redirects — highly suspicious")

        # Domain switching depth
        if len(unique_domains) >= 3:
            score += 2
            flags.append("Multiple domain changes detected")

        # URL shortener found in chain
        if any(domain in URL_SHORTENERS for domain in domains):
            score += 2
            flags.append("URL shortener detected in redirect chain")

        # Suspicious TLD present in chain
        for domain in domains:
            parts = domain.split(".")
            if len(parts) > 1:
                tld = parts[-1]
                if tld in SUSPICIOUS_TLDS:
                    score += 2
                    flags.append(f"Suspicious TLD detected: .{tld}")
                    break

        # Repeated domains / possible looping patterns
        if len(domains) != len(set(domains)):
            score += 1
            flags.append("Repeated domains detected in chain")

        return {
            "score": score,
            "flags": flags,
            "chain": chain[: max_hops + 1],
            "domains": unique_domains,
            "final_url": final_url,
            "hops": hops,
        }

    except httpx.HTTPError as e:
        return {
            "score": 1,
            "flags": [f"Redirect check failed: {e}"],
            "chain": [],
            "domains": [],
            "final_url": url,
            "hops": 0,
        }
