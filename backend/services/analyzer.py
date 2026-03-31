from urllib.parse import urlparse

from fastapi import HTTPException

from models.contracts import RiskAnalysis
from services.extensions import get_suspicious_extension
from services.gemini import summarize_risk
from services.safe_browsing import check_safe_browsing
from services.typosquatting import detect_typosquatting
from services.whoisxml import get_domain_age_days


def normalize_url(raw_url: str) -> str:
    # Accepts bare domains from QR input and normalizes to absolute URL.
    candidate = raw_url.strip()
    if not candidate.startswith(("http://", "https://")):
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL.")
    return candidate


def analyze_url(url: str) -> RiskAnalysis:
    # Central risk pipeline used by both /scan and /go.
    # Integrations from teammate modules should continue to feed this contract.
    parsed = urlparse(url)
    host = (parsed.netloc or "").lower()
    suspicious_keywords = ("login", "secure", "verify", "update", "account")
    risky_tld = host.endswith(".ru") or host.endswith(".tk")
    uses_punycode = "xn--" in host
    https_missing = parsed.scheme != "https"
    safe_browsing = check_safe_browsing(url)
    suspicious_extension = get_suspicious_extension(url)
    domain_age_days = get_domain_age_days(host)
    typosquatting_detected = detect_typosquatting(host)

    keyword_hit = any(word in host for word in suspicious_keywords)
    safe_browsing_matched = bool(safe_browsing.get("matched"))
    domain_is_new = domain_age_days is not None and domain_age_days <= 30
    flagged_threat_intel = risky_tld or uses_punycode or domain_is_new

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
    if https_missing:
        risk_score += 10
    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        risk_level = "danger"
    elif risk_score >= 35:
        risk_level = "suspicious"
    else:
        risk_level = "safe"

    threat_types = safe_browsing.get("threat_types", [])
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
    if typosquatting_detected:
        reasons.append("Possible brand impersonation / typosquatting signal.")
    if keyword_hit:
        reasons.append("Suspicious auth-related keywords detected in host.")
    if suspicious_extension:
        reasons.append(f"Suspicious file extension detected: {suspicious_extension}.")
    if https_missing:
        reasons.append("Destination does not use HTTPS.")

    ai_summary = summarize_risk(url, risk_level, reasons)
    return RiskAnalysis(
        risk_score=risk_score,
        risk_level=risk_level,
        flagged_safe_browsing=safe_browsing_matched,
        flagged_threat_intel=flagged_threat_intel,
        typosquatting_detected=typosquatting_detected,
        domain_age_days=domain_age_days,
        redirect_hops=0,
        ssl_valid=not https_missing,
        ai_summary=ai_summary,
    )
