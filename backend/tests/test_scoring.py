"""Unit tests for deterministic scoring rules."""

from __future__ import annotations

from app.core.scoring import ScoringInputs, calculate_risk_score, to_legacy_risk_analysis
from app.schemas.enums import Verdict
from app.schemas.redirects import RedirectsResult
from app.schemas.reputation import ReputationResult
from app.schemas.safe_browsing import SafeBrowsingResult
from app.schemas.ssl_info import SSLInfoResult
from app.schemas.threat_intel import ThreatIntelResult
from app.schemas.whois import WhoisResult
from app.services.url_analysis import analyze_url_value


def test_calculate_risk_score_returns_safe_for_clean_inputs() -> None:
    """No triggered rules should keep the result safe with a zero score."""

    result = calculate_risk_score(
        ScoringInputs(
            url_analysis=analyze_url_value("https://www.example.com/index.html"),
            whois=WhoisResult(
                domain="example.com",
                available=True,
                found=True,
                domain_age_days=365,
            ),
            reputation=ReputationResult(
                url="https://www.example.com/index.html",
                available=True,
                score=90,
                verdict=Verdict.SAFE,
            ),
            ssl_info=SSLInfoResult(
                host="www.example.com",
                available=True,
                has_tls=True,
                verdict=Verdict.SAFE,
            ),
            redirects=RedirectsResult(
                input_url="https://www.example.com/index.html",
                final_url="https://www.example.com/index.html",
                available=True,
                hop_count=0,
            ),
        )
    )

    assert result.score == 0
    assert result.verdict == "safe"
    assert result.score_breakdown[0].label == "clean_result"


def test_calculate_risk_score_returns_suspicious_for_noncritical_signals() -> None:
    """Young domains plus SSL issues should score as suspicious, not dangerous."""

    result = calculate_risk_score(
        ScoringInputs(
            url_analysis=analyze_url_value("https://www.example.com/login"),
            whois=WhoisResult(
                domain="example.com",
                available=True,
                found=True,
                domain_age_days=10,
            ),
            ssl_info=SSLInfoResult(
                host="www.example.com",
                available=True,
                has_tls=True,
                self_signed=True,
                verdict=Verdict.SUSPICIOUS,
                reasons=["TLS certificate appears to be self-signed."],
            ),
        )
    )

    assert result.score == 45
    assert result.verdict == "suspicious"
    assert {item.label for item in result.score_breakdown} == {
        "young_domain",
        "ssl_issues",
    }


def test_calculate_risk_score_forces_dangerous_on_safe_browsing_match() -> None:
    """Critical Safe Browsing matches should override the computed score."""

    result = calculate_risk_score(
        ScoringInputs(
            url_analysis=analyze_url_value("https://www.example.com"),
            safe_browsing=SafeBrowsingResult(
                matched=True,
                threat_types=["MALWARE"],
                raw_response={"threats": [{}]},
            ),
        )
    )

    assert result.score == 100
    assert result.verdict == "dangerous"
    assert result.flagged_safe_browsing is True
    assert "Safe Browsing positive match" in result.override_reasons


def test_calculate_risk_score_caps_total_at_one_hundred() -> None:
    """Non-critical rule combinations should still cap the total score at 100."""

    result = calculate_risk_score(
        ScoringInputs(
            url_analysis=analyze_url_value("https://раypal-secure.example.com/update.pkg"),
            whois=WhoisResult(
                domain="example.com",
                available=True,
                found=True,
                domain_age_days=5,
            ),
            reputation=ReputationResult(
                url="https://раypal-secure.example.com/update.pkg",
                available=True,
                score=15,
                verdict=Verdict.MALICIOUS,
                reasons=["Provider score is very low."],
            ),
            ssl_info=SSLInfoResult(
                host="раypal-secure.example.com",
                available=True,
                has_tls=False,
                verdict=Verdict.SUSPICIOUS,
                reasons=["TLS certificate data was not available."],
            ),
            redirects=RedirectsResult(
                input_url="https://раypal-secure.example.com/update.pkg",
                final_url="https://downloads.example.net/update.pkg",
                available=True,
                hop_count=4,
                classification="high_risk",
            ),
        )
    )

    assert result.score == 100
    assert result.verdict == "dangerous"
    assert len(result.score_breakdown) >= 5


def test_to_legacy_risk_analysis_maps_dangerous_to_danger() -> None:
    """Legacy contract adapter should translate the new dangerous verdict."""

    score_result = calculate_risk_score(
        ScoringInputs(
            url_analysis=analyze_url_value("https://www.example.com"),
            threat_intel=ThreatIntelResult(
                url="https://www.example.com",
                available=True,
                matched=True,
                verdict=Verdict.MALICIOUS,
                reasons=["Listed in threat feed."],
            ),
        )
    )

    legacy = to_legacy_risk_analysis(score_result)

    assert legacy.risk_score == 100
    assert legacy.risk_level == "danger"
    assert legacy.flagged_threat_intel is True
    assert legacy.ai_summary == score_result.summary
