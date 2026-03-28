# backend/services/redirect_checker.py

from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None


# --- Configuration ---

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

# --- Helpers ---

def extract_domain(url: str) -> str:
    """Extract domain from a URL."""
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


# --- Main Function ---

def get_redirect_chain(url: str, max_hops: int = 6) -> dict:
    """
    Analyze a URL's redirect chain for phishing/quishing indicators.

    Returns:
    {
        "score": int,
        "flags": list[str],
        "chain": list[str],
        "domains": list[str],
        "final_url": str
    }
    """

    if not requests:
        return {
            "score": 1,
            "flags": ["requests library not installed"],
            "chain": [],
            "domains": [],
            "final_url": "",
        }

    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=5,
        )

        # Build redirect chain
        chain = [resp.url for resp in response.history]
        chain.append(response.url)

        final_url = response.url

        score = 0
        flags = []

        hops = len(chain) - 1
        domains = [extract_domain(u) for u in chain]
        unique_domains = list(set(domains))

        # --- 1. Redirect Depth ---
        if hops <= 2:
            pass  # normal
        elif 3 <= hops <= 5:
            score += 2
            flags.append(f"{hops} redirects — unusual behavior")
        elif hops > 5:
            score += 3
            flags.append(f"{hops} redirects — highly suspicious")

        # --- 2. Domain Switching ---
        if len(set(domains)) >= 3:
            score += 2
            flags.append("Multiple domain changes detected")

        # --- 3. URL Shorteners ---
        if any(domain in URL_SHORTENERS for domain in domains):
            score += 2
            flags.append("URL shortener detected in redirect chain")

        # --- 4. Suspicious TLDs ---
        for domain in domains:
            parts = domain.split(".")
            if len(parts) > 1:
                tld = parts[-1]
                if tld in SUSPICIOUS_TLDS:
                    score += 2
                    flags.append(f"Suspicious TLD detected: .{tld}")
                    break

        # --- 5. Repeated Domains (loop-ish behavior) ---
        if len(domains) != len(set(domains)):
            score += 1
            flags.append("Repeated domains detected in chain")

        return {
            "score": score,
            "flags": flags,
            "chain": chain,
            "domains": unique_domains,
            "final_url": final_url,
        }

    except requests.RequestException as e:
        return {
            "score": 1,
            "flags": [f"Redirect check failed: {str(e)}"],
            "chain": [],
            "domains": [],
            "final_url": "",
        }