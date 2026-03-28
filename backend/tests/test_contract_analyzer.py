"""Tests for the contract-facing analyzer used by /scan and /go."""

import pytest
from fastapi import HTTPException

from services import analyzer


def _stub_external_feeds(monkeypatch) -> None:
    monkeypatch.setattr(
        analyzer,
        "get_redirect_chain",
        lambda url: {"score": 0, "flags": [], "chain": [url], "hops": 0},
    )
    monkeypatch.setattr(
        analyzer,
        "get_reputation_signal",
        lambda url: {"available": False, "risky": False, "score": None, "reasons": []},
    )
    monkeypatch.setattr(
        analyzer,
        "get_threat_intel_signal",
        lambda url: {"available": False, "matched": False, "indicator_count": 0, "reasons": []},
    )
    monkeypatch.setattr(
        analyzer,
        "get_ssl_signal",
        lambda host: {"available": False, "has_tls": None, "is_expired": None, "self_signed": None},
    )
    monkeypatch.setattr(analyzer, "probe_embedded_destination", lambda url: None)


def test_analyze_url_safe_when_no_signals(monkeypatch) -> None:
    _stub_external_feeds(monkeypatch)
    monkeypatch.setattr(
        analyzer,
        "check_safe_browsing",
        lambda url: {"matched": False, "threat_types": [], "error": None},
    )
    result = analyzer.analyze_url("https://example.com")
    assert result.risk_level == "safe"
    assert result.risk_score == 0
    assert result.flagged_safe_browsing is False


def test_analyze_url_suspicious_when_heuristics_hit(monkeypatch) -> None:
    _stub_external_feeds(monkeypatch)
    monkeypatch.setattr(
        analyzer,
        "check_safe_browsing",
        lambda url: {"matched": False, "threat_types": [], "error": None},
    )
    result = analyzer.analyze_url("http://secure-login-example.tk")
    assert result.risk_level == "suspicious"
    assert result.risk_score == 50
    assert result.flagged_threat_intel is True


def test_analyze_url_danger_when_safe_browsing_matches(monkeypatch) -> None:
    _stub_external_feeds(monkeypatch)
    monkeypatch.setattr(
        analyzer,
        "check_safe_browsing",
        lambda url: {
            "matched": True,
            "threat_types": ["MALWARE"],
            "error": None,
        },
    )
    result = analyzer.analyze_url("https://example.com")
    assert result.risk_level == "danger"
    assert result.risk_score == 70
    assert result.flagged_safe_browsing is True


def test_analyze_url_suspicious_for_tunnel_domain(monkeypatch) -> None:
    _stub_external_feeds(monkeypatch)
    monkeypatch.setattr(
        analyzer,
        "check_safe_browsing",
        lambda url: {"matched": False, "threat_types": [], "error": None},
    )
    monkeypatch.setattr(analyzer, "get_domain_age_days", lambda host: 1200)

    result = analyzer.analyze_url("https://725CE83F038B6F.LHR.LIFE")
    assert result.risk_level in {"suspicious", "danger"}
    assert result.risk_score >= 35
    assert result.flagged_threat_intel is True


def test_analyze_url_uses_final_redirect_destination(monkeypatch) -> None:
    _stub_external_feeds(monkeypatch)
    monkeypatch.setattr(
        analyzer,
        "get_redirect_chain",
        lambda url: {
            "score": 0,
            "flags": [],
            "chain": [url, "http://secure-paypa1-login.tk/reset.js"],
            "hops": 1,
        },
    )
    monkeypatch.setattr(
        analyzer,
        "check_safe_browsing",
        lambda url: {"matched": False, "threat_types": [], "error": None},
    )
    monkeypatch.setattr(analyzer, "get_domain_age_days", lambda host: 1000)

    result = analyzer.analyze_url("https://qrco.de/bgi1r0")
    assert result.risk_level in {"suspicious", "danger"}
    assert result.risk_score >= 35
    assert result.typosquatting_detected is True


def test_analyze_url_uses_embedded_destination_for_shortener(monkeypatch) -> None:
    _stub_external_feeds(monkeypatch)
    monkeypatch.setattr(
        analyzer,
        "check_safe_browsing",
        lambda url: {"matched": False, "threat_types": [], "error": None},
    )
    monkeypatch.setattr(
        analyzer,
        "get_redirect_chain",
        lambda url: {"score": 0, "flags": [], "chain": [url], "hops": 0},
    )
    monkeypatch.setattr(
        analyzer,
        "probe_embedded_destination",
        lambda url: "https://y0utube.com/login",
    )
    monkeypatch.setattr(analyzer, "get_domain_age_days", lambda host: 1200)

    result = analyzer.analyze_url("https://qrco.de/bgi1r0")
    assert result.risk_level in {"suspicious", "danger"}
    assert result.risk_score >= 35
    assert result.typosquatting_detected is True


def test_normalize_url_rejects_duplicate_scheme_payload() -> None:
    with pytest.raises(HTTPException):
        analyzer.normalize_url("https://HTTPS://725CE83F038B6F.LHR.LIFE")


def test_normalize_url_accepts_uppercase_scheme_and_normalizes() -> None:
    normalized = analyzer.normalize_url("HTTPS://example.com")
    assert normalized == "https://example.com"
