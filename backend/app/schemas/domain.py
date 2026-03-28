"""Shared domain models for QRoulette analysis results."""

from typing import Any

from pydantic import Field

from app.schemas.common import SchemaModel, WebUrl
from app.schemas.enums import SourceType, Verdict


class RiskSignal(SchemaModel):
    """A single risk signal collected from one source."""

    source_type: SourceType
    verdict: Verdict
    signal: str
    details: str
    confidence: float | None = Field(default=None, ge=0, le=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScoreBreakdownItem(SchemaModel):
    """One contributor to the final URL risk score."""

    source_type: SourceType
    label: str
    score: float = Field(ge=0, le=100)
    weight: float = Field(ge=0, le=1)
    rationale: str


class ScanVerdict(SchemaModel):
    """Top-level verdict for a URL analysis."""

    verdict: Verdict
    score: float = Field(ge=0, le=100)
    summary: str
    confidence: float | None = Field(default=None, ge=0, le=1)


class RedirectResult(SchemaModel):
    """Redirect chain analysis output."""

    input_url: WebUrl
    final_url: WebUrl
    chain: list[WebUrl] = Field(default_factory=list)
    hop_count: int = Field(ge=0)
    has_cross_domain_redirect: bool = False


class UrlAnalysisResult(SchemaModel):
    """Full normalized result for a URL scan."""

    input_url: WebUrl
    normalized_url: WebUrl
    normalized_scheme: str
    normalized_hostname: str
    normalized_path: str
    registrable_domain: str
    subdomain: str = ""
    has_non_ascii_domain: bool = False
    has_non_ascii_subdomain: bool = False
    has_punycode_domain: bool = False
    has_punycode_subdomain: bool = False
    has_homoglyph_lookalike: bool = False
    has_suspicious_char_substitution: bool = False
    has_suspicious_file_extension: bool = False
    suspicious_file_extension: str | None = None
    reasons: list[str] = Field(default_factory=list)
    redirect_result: RedirectResult | None = None
    risk_signals: list[RiskSignal] = Field(default_factory=list)
    score_breakdown: list[ScoreBreakdownItem] = Field(default_factory=list)
    scan_verdict: ScanVerdict
