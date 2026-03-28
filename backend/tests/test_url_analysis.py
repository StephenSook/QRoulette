"""Unit tests for URL normalization and analysis."""

import asyncio

from app.core.url_normalizer import normalize_url
from app.core.config import Settings
from app.services.base import ServiceContext
from app.services.url_analysis import URLAnalysisService


def build_service() -> URLAnalysisService:
    """Create the URL analysis service with lightweight test context."""

    context = ServiceContext(client=None, settings=Settings())  # type: ignore[arg-type]
    return URLAnalysisService(context)


def test_normalize_url_extracts_domain_and_path() -> None:
    """Normal URLs should normalize cleanly without suspicious flags."""

    normalized = normalize_url("HTTPS://WWW.Example.COM//login/../index.html")

    assert normalized.scheme == "https"
    assert normalized.hostname == "www.example.com"
    assert normalized.hostname_ascii == "www.example.com"
    assert normalized.path == "/index.html"
    assert normalized.registrable_domain == "example.com"
    assert normalized.subdomain == "www"
    assert normalized.suspicious_file_extension is None


def test_analyze_normal_domain_is_safe() -> None:
    """Benign domains should produce a safe verdict."""

    service = build_service()

    result = asyncio.run(service.analyze_url("https://www.example.com/index.html"))

    assert result.registrable_domain == "example.com"
    assert result.subdomain == "www"
    assert result.has_homoglyph_lookalike is False
    assert result.has_suspicious_char_substitution is False
    assert result.has_suspicious_file_extension is False
    assert result.scan_verdict.verdict == "safe"


def test_analyze_punycode_domain_flags_punycode() -> None:
    """Punycode domains should be identified explicitly."""

    service = build_service()

    result = asyncio.run(service.analyze_url("https://xn--pple-43d.com/"))

    assert result.has_punycode_domain is True
    assert any("punycode" in reason.lower() for reason in result.reasons)


def test_analyze_homoglyph_like_domain_flags_lookalike() -> None:
    """Unicode lookalikes should trigger homoglyph detection."""

    service = build_service()

    result = asyncio.run(service.analyze_url("https://раypal.com/security"))

    assert result.has_homoglyph_lookalike is True
    assert any("confusable" in reason.lower() for reason in result.reasons)


def test_analyze_deceptive_subdomain_flags_substitutions() -> None:
    """Numeric substitutions in a subdomain should be marked suspicious."""

    service = build_service()

    result = asyncio.run(
        service.analyze_url("https://secure-paypa1-login.example.com/review")
    )

    assert result.registrable_domain == "example.com"
    assert result.subdomain == "secure-paypa1-login"
    assert result.has_suspicious_char_substitution is True
    assert any("resembles" in reason.lower() for reason in result.reasons)


def test_analyze_suspicious_file_extension_flags_path() -> None:
    """Dangerous final file extensions should be surfaced."""

    service = build_service()

    result = asyncio.run(service.analyze_url("https://downloads.example.com/update.pkg"))

    assert result.has_suspicious_file_extension is True
    assert result.suspicious_file_extension == ".pkg"
    assert any(".pkg" in reason.lower() for reason in result.reasons)
