from urllib.parse import urlparse

from fastapi import HTTPException

from models.contracts import RiskAnalysis


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
    # Temporary fallback scoring until teammate service integrations are wired:
    # Safe Browsing, threat intel, redirect checker, and Gemini summary.
    parsed = urlparse(url)
    host = (parsed.netloc or "").lower()
    suspicious_keywords = ("login", "secure", "verify", "update", "account")
    risky_tld = host.endswith(".ru") or host.endswith(".tk")

    keyword_hit = any(word in host for word in suspicious_keywords)
    risk_score = 70 if keyword_hit or risky_tld else 10
    risk_level = "danger" if risk_score >= 70 else "safe"

    ai_summary = (
        "Potential phishing indicators detected in domain pattern."
        if risk_level == "danger"
        else "No immediate phishing indicators detected by fallback checks."
    )
    return RiskAnalysis(
        risk_score=risk_score,
        risk_level=risk_level,
        flagged_safe_browsing=False,
        flagged_threat_intel=False,
        typosquatting_detected=keyword_hit,
        domain_age_days=None,
        redirect_hops=0,
        ssl_valid=parsed.scheme == "https",
        ai_summary=ai_summary,
    )
