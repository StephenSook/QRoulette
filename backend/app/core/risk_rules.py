"""Centralized deterministic scoring rules for QRoulette."""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas.enums import SourceType

SAFE_VERDICT = "safe"
SUSPICIOUS_VERDICT = "suspicious"
DANGEROUS_VERDICT = "dangerous"

YOUNG_DOMAIN_THRESHOLD_DAYS = 30
LOW_REPUTATION_THRESHOLD = 40.0
SUSPICIOUS_REDIRECT_HOPS = 3

SUSPICIOUS_MIN_SCORE = 25
DANGEROUS_MIN_SCORE = 70
MAX_RISK_SCORE = 100


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """Static definition for one deterministic scoring rule."""

    label: str
    source_type: SourceType
    score: int
    weight: float
    rationale: str


SAFE_BROWSING_OVERRIDE = RuleDefinition(
    label="safe_browsing_match",
    source_type=SourceType.SAFE_BROWSING,
    score=MAX_RISK_SCORE,
    weight=1.0,
    rationale="Google Safe Browsing reported a malicious or unsafe URL match.",
)

THREAT_INTEL_OVERRIDE = RuleDefinition(
    label="threat_intel_match",
    source_type=SourceType.THREAT_INTEL,
    score=MAX_RISK_SCORE,
    weight=1.0,
    rationale="Threat-intelligence sources reported a positive match for this URL.",
)

TYPOSQUATTING_RULE = RuleDefinition(
    label="typosquatting_or_homoglyph",
    source_type=SourceType.URL_ANALYSIS,
    score=35,
    weight=0.35,
    rationale="Typosquatting, homoglyph, or deceptive character-substitution signals were detected.",
)

YOUNG_DOMAIN_RULE = RuleDefinition(
    label="young_domain",
    source_type=SourceType.WHOIS,
    score=30,
    weight=0.30,
    rationale="The domain appears newly registered and has less than 30 days of history.",
)

LOW_REPUTATION_RULE = RuleDefinition(
    label="low_reputation",
    source_type=SourceType.REPUTATION,
    score=30,
    weight=0.30,
    rationale="External reputation scoring indicates the destination has low trust.",
)

LONG_REDIRECT_CHAIN_RULE = RuleDefinition(
    label="redirect_chain_over_two_hops",
    source_type=SourceType.REDIRECTS,
    score=20,
    weight=0.20,
    rationale="The destination required more than two redirects before reaching its final URL.",
)

SSL_ISSUES_RULE = RuleDefinition(
    label="ssl_issues",
    source_type=SourceType.SSL_INFO,
    score=15,
    weight=0.15,
    rationale="TLS/SSL inspection surfaced certificate or transport trust issues.",
)

SUSPICIOUS_EXTENSION_RULE = RuleDefinition(
    label="suspicious_file_extension",
    source_type=SourceType.URL_ANALYSIS,
    score=20,
    weight=0.20,
    rationale="The final path ends with a suspicious file extension associated with risky downloads.",
)

CLEAN_RESULT_RULE = RuleDefinition(
    label="clean_result",
    source_type=SourceType.URL_ANALYSIS,
    score=0,
    weight=1.0,
    rationale="No configured deterministic scoring rules were triggered.",
)
