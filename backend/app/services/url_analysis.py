"""Deterministic URL analysis for QRoulette."""

from __future__ import annotations

import re

from confusable_homoglyphs import confusables

from app.core.url_normalizer import normalize_url
from app.schemas.domain import (
    RedirectResult,
    RiskSignal,
    ScanVerdict,
    ScoreBreakdownItem,
    UrlAnalysisResult,
)
from app.schemas.enums import SourceType, Verdict
from app.services.base import ServiceStub

LATIN_ALIASES = ["latin", "common"]
SUBSTITUTION_MAP = {
    "0": "o",
    "1": "l",
    "5": "s",
}


def _build_confusable_reason(label_type: str, label: str) -> tuple[bool, list[str]]:
    """Detect confusable or mixed-script lookalikes in a label."""

    if not label:
        return False, []

    findings = confusables.is_confusable(
        label,
        greedy=True,
        preferred_aliases=LATIN_ALIASES,
    )
    if not findings:
        return False, []

    dangerous = bool(confusables.is_dangerous(label, preferred_aliases=LATIN_ALIASES))
    has_non_ascii = any(ord(char) > 127 for char in label)
    if not dangerous and not has_non_ascii:
        return False, []

    examples: list[str] = []
    for finding in findings[:3]:
        homoglyphs = ", ".join(item["c"] for item in finding.get("homoglyphs", [])[:3])
        examples.append(f"{finding['character']}->{homoglyphs}")

    reason = (
        f"{label_type} '{label}' contains characters visually confusable with Latin text"
    )
    if examples:
        reason = f"{reason} ({'; '.join(examples)})."
    else:
        reason = f"{reason}."
    return True, [reason]


def _build_substitution_reason(label_type: str, value: str) -> tuple[bool, list[str]]:
    """Detect suspicious numeric substitutions in a label."""

    reasons: list[str] = []
    for token in re.split(r"[.\-]", value):
        if not token:
            continue

        lowered = token.lower()
        substitutions = [char for char in lowered if char in SUBSTITUTION_MAP]
        if not substitutions:
            continue

        letters_or_subs = sum(
            1
            for char in lowered
            if char.isalpha() or char in SUBSTITUTION_MAP
        )
        if letters_or_subs < 4:
            continue

        replaced = "".join(SUBSTITUTION_MAP.get(char, char) for char in lowered)
        reasons.append(
            f"{label_type} token '{token}' uses suspicious substitutions and resembles '{replaced}'."
        )

    return bool(reasons), reasons


def _append_signal(
    signal_bucket: list[RiskSignal],
    reason: str,
    verdict: Verdict,
    signal: str,
    metadata: dict[str, object] | None = None,
) -> None:
    """Append a normalized risk signal."""

    signal_bucket.append(
        RiskSignal(
            source_type=SourceType.URL_ANALYSIS,
            verdict=verdict,
            signal=signal,
            details=reason,
            confidence=0.9 if verdict != Verdict.UNKNOWN else 0.0,
            metadata=metadata or {},
        )
    )


def _score_result(result: UrlAnalysisResult) -> tuple[int, Verdict, list[ScoreBreakdownItem]]:
    """Convert boolean flags into a deterministic score and verdict."""

    components: list[tuple[str, int, str]] = []
    if result.has_homoglyph_lookalike:
        components.append(("homoglyph_lookalike", 70, "Detected confusable lookalike characters."))
    if result.has_suspicious_char_substitution:
        components.append(("suspicious_substitution", 45, "Detected numeric character substitutions."))
    if result.has_punycode_domain or result.has_punycode_subdomain:
        components.append(("punycode", 25, "Detected punycode-encoded labels."))
    if result.has_non_ascii_domain or result.has_non_ascii_subdomain:
        components.append(("non_ascii", 15, "Detected non-ASCII characters in hostname labels."))
    if result.has_suspicious_file_extension:
        components.append(("suspicious_extension", 35, "Detected a high-risk final file extension."))

    score = min(100, sum(component[1] for component in components))
    if score >= 80:
        verdict = Verdict.MALICIOUS
    elif score > 0:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.SAFE

    breakdown = [
        ScoreBreakdownItem(
            source_type=SourceType.URL_ANALYSIS,
            label=label,
            score=value,
            weight=1.0,
            rationale=rationale,
        )
        for label, value, rationale in components
    ]
    if not breakdown:
        breakdown.append(
            ScoreBreakdownItem(
                source_type=SourceType.URL_ANALYSIS,
                label="clean_domain_signals",
                score=0,
                weight=1.0,
                rationale="No suspicious domain/subdomain or file extension indicators were found.",
            )
        )

    return score, verdict, breakdown


def analyze_url_value(url: str) -> UrlAnalysisResult:
    """Analyze a URL deterministically using local normalization heuristics."""

    normalized = normalize_url(url)
    reasons: list[str] = []
    risk_signals: list[RiskSignal] = []

    if normalized.has_non_ascii_domain:
        reason = "Registrable domain contains non-ASCII characters."
        reasons.append(reason)
        _append_signal(risk_signals, reason, Verdict.SUSPICIOUS, "non_ascii_domain")

    if normalized.has_non_ascii_subdomain:
        reason = "Subdomain contains non-ASCII characters."
        reasons.append(reason)
        _append_signal(risk_signals, reason, Verdict.SUSPICIOUS, "non_ascii_subdomain")

    if normalized.has_punycode_domain:
        reason = "Registrable domain contains punycode labels."
        reasons.append(reason)
        _append_signal(risk_signals, reason, Verdict.SUSPICIOUS, "punycode_domain")

    if normalized.has_punycode_subdomain:
        reason = "Subdomain contains punycode labels."
        reasons.append(reason)
        _append_signal(risk_signals, reason, Verdict.SUSPICIOUS, "punycode_subdomain")

    has_homoglyph_domain, homoglyph_domain_reasons = _build_confusable_reason(
        "Registrable domain",
        normalized.registrable_domain,
    )
    has_homoglyph_subdomain, homoglyph_subdomain_reasons = _build_confusable_reason(
        "Subdomain",
        normalized.subdomain,
    )
    has_homoglyph_lookalike = has_homoglyph_domain or has_homoglyph_subdomain
    for reason in [*homoglyph_domain_reasons, *homoglyph_subdomain_reasons]:
        reasons.append(reason)
        _append_signal(risk_signals, reason, Verdict.SUSPICIOUS, "homoglyph_lookalike")

    has_substitution_domain, substitution_domain_reasons = _build_substitution_reason(
        "Registrable domain",
        normalized.registrable_domain,
    )
    has_substitution_subdomain, substitution_subdomain_reasons = _build_substitution_reason(
        "Subdomain",
        normalized.subdomain,
    )
    has_suspicious_char_substitution = (
        has_substitution_domain or has_substitution_subdomain
    )
    for reason in [*substitution_domain_reasons, *substitution_subdomain_reasons]:
        reasons.append(reason)
        _append_signal(
            risk_signals,
            reason,
            Verdict.SUSPICIOUS,
            "suspicious_char_substitution",
        )

    has_suspicious_file_extension = normalized.suspicious_file_extension is not None
    if has_suspicious_file_extension:
        reason = (
            "Final path ends with suspicious file extension "
            f"'{normalized.suspicious_file_extension}'."
        )
        reasons.append(reason)
        _append_signal(
            risk_signals,
            reason,
            Verdict.SUSPICIOUS,
            "suspicious_file_extension",
            metadata={"extension": normalized.suspicious_file_extension},
        )

    redirect_result = RedirectResult(
        input_url=normalized.original_url,
        final_url=normalized.normalized_url,
        chain=[normalized.normalized_url],
        hop_count=0,
        has_cross_domain_redirect=False,
    )

    result = UrlAnalysisResult(
        input_url=normalized.original_url,
        normalized_url=normalized.normalized_url,
        normalized_scheme=normalized.scheme,
        normalized_hostname=normalized.hostname_ascii,
        normalized_path=normalized.path,
        registrable_domain=normalized.registrable_domain,
        subdomain=normalized.subdomain,
        has_non_ascii_domain=normalized.has_non_ascii_domain,
        has_non_ascii_subdomain=normalized.has_non_ascii_subdomain,
        has_punycode_domain=normalized.has_punycode_domain,
        has_punycode_subdomain=normalized.has_punycode_subdomain,
        has_homoglyph_lookalike=has_homoglyph_lookalike,
        has_suspicious_char_substitution=has_suspicious_char_substitution,
        has_suspicious_file_extension=has_suspicious_file_extension,
        suspicious_file_extension=normalized.suspicious_file_extension,
        reasons=reasons,
        redirect_result=redirect_result,
        risk_signals=risk_signals,
        score_breakdown=[],
        scan_verdict=ScanVerdict(
            verdict=Verdict.UNKNOWN,
            score=0,
            summary="URL analysis in progress.",
            confidence=0.0,
        ),
    )

    score, verdict, score_breakdown = _score_result(result)
    result.score_breakdown = score_breakdown
    result.scan_verdict = ScanVerdict(
        verdict=verdict,
        score=score,
        summary=(
            "No suspicious URL-analysis indicators were found."
            if verdict == Verdict.SAFE
            else "Suspicious URL-analysis indicators were detected."
            if verdict == Verdict.SUSPICIOUS
            else "Multiple high-confidence suspicious indicators were detected."
        ),
        confidence=0.95 if verdict != Verdict.SAFE else 0.8,
    )
    return result


class URLAnalysisService(ServiceStub):
    """Coordinate deterministic URL analysis for local phishing signals."""

    async def analyze_url(self, url: str) -> UrlAnalysisResult:
        """Return deterministic domain/subdomain analysis for a URL."""

        return analyze_url_value(url)
