import re
from urllib.parse import urlparse
from fastapi import HTTPException

from models.contracts import RiskAnalysis
from services.content_probe import probe_embedded_destination
from services.extensions import get_suspicious_extension
from services.gemini import summarize_risk
from services.intel_feeds import (
    get_reputation_signal,
    get_ssl_signal,
    get_threat_intel_signal,
)
from services.redirect_checker import get_redirect_chain
from services.safe_browsing import check_safe_browsing
from services.typosquatting import detect_typosquatting
from services.whoisxml import get_domain_age_days

TUNNEL_SUFFIXES = (
    ".lhr.life",
    ".localhost.run",
    ".ngrok.io",
    ".ngrok-free.app",
    ".trycloudflare.com",
    ".loca.lt",
    ".serveo.net",
)

URL_SHORTENER_HOSTS = (
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "short.io",
    "qrco.de",
    "qrln.org",
)

STATIC_ASSET_EXTENSIONS = (
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".css",
    ".js",
    ".woff",
    ".woff2",
)


def _is_high_entropy_label(host: str) -> bool:
    """
    Detect machine-generated first labels used by ephemeral phishing tunnels.
    Example: 725ce83f038b6f.lhr.life
    """
    labels = [part for part in host.split(".") if part]
    if not labels:
        return False
    first = labels[0].lower()
    if len(first) < 12:
        return False
    # A long mostly-hex label is a strong tunnel/phishing signal.
    if re.fullmatch(r"[a-f0-9]{12,}", first):
        return True
    return False


def normalize_url(raw_url: str) -> str:
    # Accepts bare domains from QR input and normalizes to absolute URL.
    candidate = raw_url.strip()
    if not candidate:
        raise HTTPException(status_code=400, detail="Invalid URL.")

    parsed_raw = urlparse(candidate)
    if parsed_raw.scheme:
        if parsed_raw.scheme.lower() not in {"http", "https"}:
            raise HTTPException(status_code=400, detail="Invalid URL scheme.")
        # Keep a normalized lowercase scheme for downstream checks.
        candidate = f"{parsed_raw.scheme.lower()}://{candidate.split('://', 1)[1]}"
    else:
        candidate = f"https://{candidate}"

    # Reject malformed payloads such as "https://HTTPS://example.com".
    tail = candidate.split("://", 1)[1]
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", tail):
        raise HTTPException(status_code=400, detail="Invalid URL.")

    parsed = urlparse(candidate)
    host = (parsed.hostname or "").strip().lower()
    if not parsed.netloc or not host or host in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Invalid URL.")
    return candidate


def analyze_url(url: str) -> RiskAnalysis:
    # Central risk pipeline used by both /scan and /go.
    # Integrations from teammate modules should continue to feed this contract.
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    suspicious_keywords = ("login", "secure", "verify", "update", "account")
    redirect_chain = get_redirect_chain(url)
    redirect_hops = int(redirect_chain.get("hops", 0) or 0)
    chain = redirect_chain.get("chain", [])
    chain = [item for item in chain if isinstance(item, str) and item]
    final_url = chain[-1] if chain else url
    target_url = final_url
    embedded_destination = None
    if redirect_hops == 0 and any(
        host == shortener or host.endswith(f".{shortener}") for shortener in URL_SHORTENER_HOSTS
    ):
        embedded_destination = probe_embedded_destination(url)
        if embedded_destination:
            target_url = embedded_destination
    embedded_asset_only = False
    if embedded_destination:
        embedded_path = (urlparse(embedded_destination).path or "").lower()
        embedded_asset_only = embedded_path.endswith(STATIC_ASSET_EXTENSIONS)

    final_parsed = urlparse(target_url)
    final_host = (final_parsed.hostname or "").lower()
    target_url = target_url if final_host else url
    target_host = final_host if final_host else host

    risky_tld = target_host.endswith(".ru") or target_host.endswith(".tk")
    tunnel_domain = target_host.endswith(TUNNEL_SUFFIXES)
    high_entropy_label = _is_high_entropy_label(target_host)
    uses_punycode = "xn--" in target_host
    https_missing = final_parsed.scheme != "https"
    safe_browsing = check_safe_browsing(url)
    safe_browsing_target = check_safe_browsing(target_url) if target_url != url else safe_browsing
    safe_browsing_matched = bool(safe_browsing.get("matched")) or bool(safe_browsing_target.get("matched"))
    safe_browsing_types = sorted(
        {
            *(safe_browsing.get("threat_types", []) or []),
            *(safe_browsing_target.get("threat_types", []) or []),
        }
    )
    suspicious_extension = get_suspicious_extension(target_url)
    domain_age_days = get_domain_age_days(target_host)
    typosquatting_detected = detect_typosquatting(target_host)
    reputation_signal = get_reputation_signal(target_url)
    threat_intel_signal = get_threat_intel_signal(target_url)
    ssl_signal = get_ssl_signal(target_host)
    ssl_provider_valid = ssl_signal.get("has_tls")
    ssl_valid = (not https_missing) and (
        True if not isinstance(ssl_provider_valid, bool) else ssl_provider_valid
    )
    from_shortener = any(
        host == shortener or host.endswith(f".{shortener}") for shortener in URL_SHORTENER_HOSTS
    )
    cross_domain_redirect = False
    if len(chain) >= 2:
        start_host = (urlparse(chain[0]).hostname or "").lower()
        end_host = (urlparse(chain[-1]).hostname or "").lower()
        cross_domain_redirect = bool(start_host and end_host and start_host != end_host)
    unresolved_shortener = from_shortener and redirect_hops == 0 and not embedded_destination

    target_path = (final_parsed.path or "").lower()
    keyword_hit = any(word in target_host or word in target_path for word in suspicious_keywords)
    domain_is_new = domain_age_days is not None and domain_age_days <= 30
    reputation_risky = bool(reputation_signal.get("risky"))
    threat_intel_matched = bool(threat_intel_signal.get("matched"))
    flagged_threat_intel = (
        risky_tld
        or uses_punycode
        or domain_is_new
        or tunnel_domain
        or high_entropy_label
        or reputation_risky
        or threat_intel_matched
    )

    risk_score = 0
    if safe_browsing_matched:
        risk_score += 70
    if flagged_threat_intel:
        risk_score += 20
    if typosquatting_detected:
        risk_score += 25
    if keyword_hit:
        risk_score += 10
    if suspicious_extension:
        risk_score += 20
    if tunnel_domain:
        risk_score += 25
    if high_entropy_label:
        risk_score += 20
    if from_shortener and redirect_hops >= 1:
        risk_score += 25
    if cross_domain_redirect:
        risk_score += 10
    if embedded_destination:
        risk_score += 25
        if embedded_asset_only:
            risk_score += 20
    elif unresolved_shortener:
        risk_score += 10
    if redirect_hops >= 3:
        risk_score += 15
    if reputation_risky:
        risk_score += 25
    if threat_intel_matched:
        risk_score += 30
    if ssl_signal.get("is_expired") is True:
        risk_score += 10
    if ssl_signal.get("self_signed") is True:
        risk_score += 10
    if https_missing:
        risk_score += 10
    if not ssl_valid:
        risk_score += 10
    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        risk_level = "danger"
    elif risk_score >= 35:
        risk_level = "suspicious"
    else:
        risk_level = "safe"

    threat_types = safe_browsing_types
    reasons: list[str] = []
    if safe_browsing_matched:
        reasons.append(
            "Safe Browsing matched threats: "
            + (", ".join(threat_types) if threat_types else "unknown")
        )
    if flagged_threat_intel:
        if risky_tld:
            reasons.append("High-risk TLD detected.")
        if uses_punycode:
            reasons.append("Punycode domain pattern detected.")
        if domain_is_new:
            reasons.append("Very new domain based on Whois age.")
        if tunnel_domain:
            reasons.append("Temporary tunnel domain pattern detected.")
        if high_entropy_label:
            reasons.append("Randomized high-entropy host label detected.")
        if from_shortener and redirect_hops >= 1:
            reasons.append("URL shortener redirected to a downstream destination.")
        if cross_domain_redirect:
            reasons.append("Redirect chain crosses domains.")
        if embedded_destination:
            reasons.append("Short-link preview exposed an embedded downstream destination.")
            if embedded_asset_only:
                reasons.append("Embedded destination appears to be a static asset, not a navigable final page.")
        if reputation_risky:
            reputation_score = reputation_signal.get("score")
            if isinstance(reputation_score, (int, float)):
                reasons.append(f"Low reputation score from external feed: {reputation_score:.1f}.")
            else:
                reasons.append("Low reputation signal from external feed.")
        if threat_intel_matched:
            reasons.append("Threat-intelligence feed matched this URL.")
    if typosquatting_detected:
        reasons.append("Possible brand impersonation / typosquatting signal.")
    if keyword_hit:
        reasons.append("Suspicious auth-related keywords detected in host.")
    if suspicious_extension:
        reasons.append(f"Suspicious file extension detected: {suspicious_extension}.")
    if redirect_hops >= 3:
        reasons.append(f"Redirect chain has {redirect_hops} hops.")
    if target_url != url:
        reasons.append(f"Resolved destination analyzed: {target_url}.")
    elif unresolved_shortener:
        reasons.append("Short-link host detected; destination could not be resolved automatically.")
    if https_missing:
        reasons.append("Destination does not use HTTPS.")
    if ssl_signal.get("is_expired") is True:
        reasons.append("TLS certificate appears expired.")
    if ssl_signal.get("self_signed") is True:
        reasons.append("TLS certificate appears self-signed.")
    if not ssl_valid:
        reasons.append("TLS provider reported invalid/missing certificate.")
    for reason in reputation_signal.get("reasons", [])[:2]:
        if isinstance(reason, str) and reason:
            reasons.append(f"Reputation feed: {reason}")
    for reason in threat_intel_signal.get("reasons", [])[:2]:
        if isinstance(reason, str) and reason:
            reasons.append(f"Threat intel feed: {reason}")

    ai_summary = summarize_risk(url, risk_level, reasons)
    return RiskAnalysis(
        risk_score=risk_score,
        risk_level=risk_level,
        flagged_safe_browsing=safe_browsing_matched,
        flagged_threat_intel=flagged_threat_intel,
        typosquatting_detected=typosquatting_detected,
        domain_age_days=domain_age_days,
        redirect_hops=redirect_hops,
        ssl_valid=ssl_valid,
        ai_summary=ai_summary,
    )
