"""Tests for the contract-facing analyzer used by /scan and /go."""

from services import analyzer


def test_analyze_url_safe_when_no_signals(monkeypatch) -> None:
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
    monkeypatch.setattr(
        analyzer,
        "check_safe_browsing",
        lambda url: {"matched": False, "threat_types": [], "error": None},
    )
    result = analyzer.analyze_url("http://secure-login-example.tk")
    assert result.risk_level == "suspicious"
    assert result.risk_score == 40
    assert result.flagged_threat_intel is True


def test_analyze_url_danger_when_safe_browsing_matches(monkeypatch) -> None:
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
