"""Deterministic scoring engine for QRoulette risk signals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import Field

from app.core.risk_rules import (
    CLEAN_RESULT_RULE,
    DANGEROUS_MIN_SCORE,
    DANGEROUS_VERDICT,
    LONG_REDIRECT_CHAIN_RULE,
    LOW_REPUTATION_RULE,
    LOW_REPUTATION_THRESHOLD,
    MAX_RISK_SCORE,
    SAFE_BROWSING_OVERRIDE,
    SAFE_VERDICT,
    SSL_ISSUES_RULE,
    SUSPICIOUS_EXTENSION_RULE,
    SUSPICIOUS_MIN_SCORE,
    SUSPICIOUS_VERDICT,
    SUSPICIOUS_REDIRECT_HOPS,
    THREAT_INTEL_OVERRIDE,
    TYPOSQUATTING_RULE,
    YOUNG_DOMAIN_RULE,
    YOUNG_DOMAIN_THRESHOLD_DAYS,
    RuleDefinition,
)
from app.schemas.common import SchemaModel
from app.schemas.domain import ScoreBreakdownItem, UrlAnalysisResult
from app.schemas.enums import Verdict
from app.schemas.redirects import RedirectsResult
from app.schemas.reputation import ReputationResult
from app.schemas.safe_browsing import SafeBrowsingResult
from app.schemas.ssl_info import SSLInfoResult
from app.schemas.threat_intel import ThreatIntelResult
from app.schemas.whois import WhoisResult
from models.contracts import RiskAnalysis

ScoringVerdict = Literal["safe", "suspicious", "dangerous"]


@dataclass(slots=True)
class ScoringInputs:
    """Normalized inputs consumed by the deterministic scoring engine."""

    url_analysis: UrlAnalysisResult
    safe_browsing: SafeBrowsingResult | None = None
    whois: WhoisResult | None = None
    reputation: ReputationResult | None = None
    threat_intel: ThreatIntelResult | None = None
    ssl_info: SSLInfoResult | None = None
    redirects: RedirectsResult | None = None


class DeterministicScoreResult(SchemaModel):
    """Canonical output of the deterministic scoring engine."""

    score: int = Field(ge=0, le=100)
    verdict: ScoringVerdict
    summary: str
    score_breakdown: list[ScoreBreakdownItem] = Field(default_factory=list)
    override_reasons: list[str] = Field(default_factory=list)
    flagged_safe_browsing: bool = False
    flagged_threat_intel: bool = False
    typosquatting_detected: bool = False
    domain_age_days: int | None = None
    redirect_hops: int = 0
    ssl_valid: bool = True


def _build_breakdown_item(rule: RuleDefinition, rationale: str | None = None) -> ScoreBreakdownItem:
    """Translate a rule definition into a breakdown item."""

    return ScoreBreakdownItem(
        source_type=rule.source_type,
        label=rule.label,
        score=rule.score,
        weight=rule.weight,
        rationale=rationale or rule.rationale,
    )


def _first_reason(reasons: list[str], fallback: str) -> str:
    """Return the first non-empty reason from a list."""

    for reason in reasons:
        if reason:
            return reason
    return fallback


def _is_low_reputation(result: ReputationResult | None) -> bool:
    """Return whether reputation data should count as a high-weight risk signal."""

    if result is None or not result.available:
        return False
    if result.score is not None:
        return result.score <= LOW_REPUTATION_THRESHOLD
    return result.verdict in {Verdict.SUSPICIOUS, Verdict.MALICIOUS}


def _has_ssl_issues(result: SSLInfoResult | None) -> bool:
    """Return whether TLS/SSL data should count as a medium-weight risk signal."""

    if result is None or not result.available:
        return False
    return (
        not result.has_tls
        or bool(result.is_expired)
        or bool(result.self_signed)
        or result.verdict in {Verdict.SUSPICIOUS, Verdict.MALICIOUS}
    )


def _typosquatting_detected(url_analysis: UrlAnalysisResult) -> bool:
    """Return whether local URL analysis detected typo/deceptive domain signals."""

    return any(
        (
            url_analysis.has_homoglyph_lookalike,
            url_analysis.has_suspicious_char_substitution,
            url_analysis.has_punycode_domain,
            url_analysis.has_punycode_subdomain,
        )
    )


def _score_to_verdict(score: int) -> ScoringVerdict:
    """Map a bounded score to the scoring engine verdict vocabulary."""

    if score >= DANGEROUS_MIN_SCORE:
        return DANGEROUS_VERDICT
    if score >= SUSPICIOUS_MIN_SCORE:
        return SUSPICIOUS_VERDICT
    return SAFE_VERDICT


def _build_summary(verdict: ScoringVerdict, override_reasons: list[str]) -> str:
    """Build a short deterministic verdict summary."""

    if override_reasons:
        return "Critical threat sources flagged the destination as dangerous."
    if verdict == DANGEROUS_VERDICT:
        return "Multiple high-confidence risk signals indicate a dangerous destination."
    if verdict == SUSPICIOUS_VERDICT:
        return "Deterministic risk rules found suspicious signals that warrant caution."
    return "No configured deterministic risk signals were triggered."


def calculate_risk_score(inputs: ScoringInputs) -> DeterministicScoreResult:
    """Aggregate normalized service outputs into a deterministic risk score."""

    breakdown: list[ScoreBreakdownItem] = []
    override_reasons: list[str] = []

    flagged_safe_browsing = bool(inputs.safe_browsing and inputs.safe_browsing.matched)
    if flagged_safe_browsing:
        rationale = SAFE_BROWSING_OVERRIDE.rationale
        if inputs.safe_browsing and inputs.safe_browsing.threat_types:
            rationale = (
                f"{rationale} Threat types: {', '.join(inputs.safe_browsing.threat_types)}."
            )
        breakdown.append(_build_breakdown_item(SAFE_BROWSING_OVERRIDE, rationale))
        override_reasons.append("Safe Browsing positive match")

    flagged_threat_intel = bool(inputs.threat_intel and inputs.threat_intel.matched)
    if flagged_threat_intel:
        rationale = _first_reason(
            inputs.threat_intel.reasons if inputs.threat_intel else [],
            THREAT_INTEL_OVERRIDE.rationale,
        )
        breakdown.append(_build_breakdown_item(THREAT_INTEL_OVERRIDE, rationale))
        override_reasons.append("Threat-intel positive match")

    typosquatting_detected = _typosquatting_detected(inputs.url_analysis)
    if typosquatting_detected:
        rationale = _first_reason(inputs.url_analysis.reasons, TYPOSQUATTING_RULE.rationale)
        breakdown.append(_build_breakdown_item(TYPOSQUATTING_RULE, rationale))

    domain_age_days = inputs.whois.domain_age_days if inputs.whois else None
    if (
        inputs.whois
        and inputs.whois.available
        and inputs.whois.domain_age_days is not None
        and inputs.whois.domain_age_days < YOUNG_DOMAIN_THRESHOLD_DAYS
    ):
        rationale = (
            f"WHOIS data shows the domain is {inputs.whois.domain_age_days} days old, "
            f"which is below the {YOUNG_DOMAIN_THRESHOLD_DAYS}-day threshold."
        )
        breakdown.append(_build_breakdown_item(YOUNG_DOMAIN_RULE, rationale))

    if _is_low_reputation(inputs.reputation):
        reputation_score = (
            f"{inputs.reputation.score:.0f}" if inputs.reputation and inputs.reputation.score is not None else "unknown"
        )
        rationale = _first_reason(
            inputs.reputation.reasons if inputs.reputation else [],
            f"Reputation data is low confidence/trust with a score of {reputation_score}.",
        )
        breakdown.append(_build_breakdown_item(LOW_REPUTATION_RULE, rationale))

    redirect_hops = inputs.redirects.hop_count if inputs.redirects else 0
    if inputs.redirects and inputs.redirects.available and inputs.redirects.hop_count >= SUSPICIOUS_REDIRECT_HOPS:
        rationale = (
            f"Redirect inspection observed {inputs.redirects.hop_count} hops before the final destination."
        )
        breakdown.append(_build_breakdown_item(LONG_REDIRECT_CHAIN_RULE, rationale))

    ssl_valid = not _has_ssl_issues(inputs.ssl_info)
    if _has_ssl_issues(inputs.ssl_info):
        rationale = _first_reason(
            inputs.ssl_info.reasons if inputs.ssl_info else [],
            SSL_ISSUES_RULE.rationale,
        )
        breakdown.append(_build_breakdown_item(SSL_ISSUES_RULE, rationale))

    if inputs.url_analysis.has_suspicious_file_extension:
        rationale = _first_reason(
            inputs.url_analysis.reasons,
            SUSPICIOUS_EXTENSION_RULE.rationale,
        )
        breakdown.append(_build_breakdown_item(SUSPICIOUS_EXTENSION_RULE, rationale))

    if not breakdown:
        breakdown.append(_build_breakdown_item(CLEAN_RESULT_RULE))

    non_override_score = sum(
        int(item.score)
        for item in breakdown
        if item.label not in {SAFE_BROWSING_OVERRIDE.label, THREAT_INTEL_OVERRIDE.label}
    )
    score = MAX_RISK_SCORE if override_reasons else min(MAX_RISK_SCORE, non_override_score)
    verdict = DANGEROUS_VERDICT if override_reasons else _score_to_verdict(score)

    return DeterministicScoreResult(
        score=score,
        verdict=verdict,
        summary=_build_summary(verdict, override_reasons),
        score_breakdown=breakdown,
        override_reasons=override_reasons,
        flagged_safe_browsing=flagged_safe_browsing,
        flagged_threat_intel=flagged_threat_intel,
        typosquatting_detected=typosquatting_detected,
        domain_age_days=domain_age_days,
        redirect_hops=redirect_hops,
        ssl_valid=ssl_valid,
    )


def to_legacy_risk_analysis(result: DeterministicScoreResult) -> RiskAnalysis:
    """Map the new scoring result into the legacy shared contract."""

    legacy_risk_level: Literal["safe", "suspicious", "danger"] = (
        "danger" if result.verdict == DANGEROUS_VERDICT else result.verdict
    )
    return RiskAnalysis(
        risk_score=result.score,
        risk_level=legacy_risk_level,
        flagged_safe_browsing=result.flagged_safe_browsing,
        flagged_threat_intel=result.flagged_threat_intel,
        typosquatting_detected=result.typosquatting_detected,
        domain_age_days=result.domain_age_days,
        redirect_hops=result.redirect_hops,
        ssl_valid=result.ssl_valid,
        ai_summary=result.summary,
    )
