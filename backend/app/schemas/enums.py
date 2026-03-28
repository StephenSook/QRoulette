"""Shared enums for API and domain models."""

from enum import Enum


class SourceType(str, Enum):
    """Upstream source categories used in risk analysis."""

    SAFE_BROWSING = "safe_browsing"
    WHOIS = "whois"
    REPUTATION = "reputation"
    THREAT_INTEL = "threat_intel"
    SSL_INFO = "ssl_info"
    REDIRECTS = "redirects"
    URL_ANALYSIS = "url_analysis"
    GEMINI = "gemini"
    QR_GENERATOR = "qr_generator"
    SUPABASE_REPO = "supabase_repo"


class Verdict(str, Enum):
    """Normalized verdict values returned by the backend."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"
