"""Main scan orchestration flow for QRoulette."""

from __future__ import annotations

import asyncio
from uuid import uuid4

from app.core.scoring import ScoringInputs, calculate_risk_score
from app.schemas.domain import RedirectResult
from app.schemas.gemini import GeminiExplanationResult
from app.schemas.persistence import PersistenceResult
from app.schemas.redirects import RedirectsResult
from app.schemas.reputation import ReputationResult
from app.schemas.safe_browsing import SafeBrowsingResult
from app.schemas.scan import ScanAnalyzeResponse
from app.schemas.ssl_info import SSLInfoResult
from app.schemas.threat_intel import ThreatIntelResult
from app.schemas.whois import WhoisResult
from app.services.base import ServiceStub


class ScanAnalysisService(ServiceStub):
    """Coordinate the full scan analysis workflow."""

    def __init__(
        self,
        context,
        *,
        url_analysis_service,
        safe_browsing_service,
        whois_service,
        reputation_service,
        threat_intel_service,
        ssl_info_service,
        redirects_service,
        gemini_service,
        supabase_repository,
        logger,
    ) -> None:
        super().__init__(context)
        self.url_analysis_service = url_analysis_service
        self.safe_browsing_service = safe_browsing_service
        self.whois_service = whois_service
        self.reputation_service = reputation_service
        self.threat_intel_service = threat_intel_service
        self.ssl_info_service = ssl_info_service
        self.redirects_service = redirects_service
        self.gemini_service = gemini_service
        self.supabase_repository = supabase_repository
        self.logger = logger

    async def _run_safe_browsing(self, scan_id: str, url: str) -> SafeBrowsingResult:
        """Call Safe Browsing without allowing exceptions to fail the scan."""

        try:
            return await self.safe_browsing_service.check_url(url)
        except Exception as exc:
            self.logger.warning(
                "Safe Browsing failed for %s: %s",
                url,
                exc,
                extra={"scan_id": scan_id},
            )
            return SafeBrowsingResult(
                matched=False,
                threat_types=[],
                raw_response={"error": str(exc)},
            )

    async def _run_whois(self, scan_id: str, domain: str) -> WhoisResult:
        """Call WHOIS without allowing exceptions to fail the scan."""

        try:
            return await self.whois_service.lookup_domain(domain)
        except Exception as exc:
            self.logger.warning(
                "WHOIS failed for %s: %s",
                domain,
                exc,
                extra={"scan_id": scan_id},
            )
            return WhoisResult(
                domain=domain,
                available=False,
                found=False,
                error=str(exc),
            )

    async def _run_reputation(self, scan_id: str, url: str) -> ReputationResult:
        """Call reputation scoring without allowing exceptions to fail the scan."""

        try:
            return await self.reputation_service.score_url(url)
        except Exception as exc:
            self.logger.warning(
                "Reputation failed for %s: %s",
                url,
                exc,
                extra={"scan_id": scan_id},
            )
            return ReputationResult(
                url=url,
                available=False,
                error=str(exc),
            )

    async def _run_threat_intel(self, scan_id: str, url: str) -> ThreatIntelResult:
        """Call threat intel without allowing exceptions to fail the scan."""

        try:
            return await self.threat_intel_service.lookup_indicators(url)
        except Exception as exc:
            self.logger.warning(
                "Threat intel failed for %s: %s",
                url,
                exc,
                extra={"scan_id": scan_id},
            )
            return ThreatIntelResult(
                url=url,
                available=False,
                error=str(exc),
            )

    async def _run_ssl_info(self, scan_id: str, host: str) -> SSLInfoResult:
        """Call SSL inspection without allowing exceptions to fail the scan."""

        try:
            return await self.ssl_info_service.inspect_host(host)
        except Exception as exc:
            self.logger.warning(
                "SSL inspection failed for %s: %s",
                host,
                exc,
                extra={"scan_id": scan_id},
            )
            return SSLInfoResult(
                host=host,
                available=False,
                error=str(exc),
            )

    async def _run_redirects(self, scan_id: str, url: str) -> RedirectsResult:
        """Call redirect inspection without allowing exceptions to fail the scan."""

        try:
            return await self.redirects_service.inspect_chain(url)
        except Exception as exc:
            self.logger.warning(
                "Redirect inspection failed for %s: %s",
                url,
                exc,
                extra={"scan_id": scan_id},
            )
            return RedirectsResult(
                input_url=url,
                final_url=url,
                available=False,
                error=str(exc),
            )

    async def _run_gemini(
        self,
        *,
        scan_id: str,
        url: str,
        verdict: str,
        score: int,
        score_breakdown,
    ) -> GeminiExplanationResult:
        """Request an optional human-readable explanation."""

        try:
            return await self.gemini_service.review_url(
                url=url,
                verdict=verdict,
                score=score,
                score_breakdown=score_breakdown,
            )
        except Exception as exc:
            self.logger.warning(
                "Gemini explanation failed for %s: %s",
                url,
                exc,
                extra={"scan_id": scan_id},
            )
            return GeminiExplanationResult(
                available=False,
                model=self.context.settings.gemini_model,
                error=str(exc),
            )

    async def _persist_scan(
        self,
        *,
        scan_id: str,
        payload: dict[str, object],
    ) -> PersistenceResult:
        """Persist scan data without failing the overall request."""

        try:
            return await self.supabase_repository.save_scan_result(payload)
        except Exception as exc:
            self.logger.warning(
                "Supabase persistence failed for scan %s: %s",
                scan_id,
                exc,
                extra={"scan_id": scan_id},
            )
            return PersistenceResult(
                available=False,
                persisted=False,
                error=str(exc),
            )

    def _apply_redirect_result(self, analysis, redirects_result) -> None:
        """Populate redirect metadata on the analysis payload when available."""

        if redirects_result is None or not redirects_result.available:
            return

        chain = [hop.url for hop in redirects_result.hops]
        if not chain or chain[-1] != redirects_result.final_url:
            chain.append(redirects_result.final_url)

        analysis.redirect_result = RedirectResult(
            input_url=analysis.input_url,
            final_url=redirects_result.final_url,
            chain=chain,
            hop_count=redirects_result.hop_count,
            has_cross_domain_redirect=redirects_result.has_cross_domain_redirect,
        )

    async def _build_effective_analysis(
        self,
        *,
        original_analysis,
        redirects_result: RedirectsResult,
    ):
        """Analyze the resolved destination when redirect inspection finds one."""

        if not redirects_result.available:
            return original_analysis

        resolved_url = redirects_result.final_url
        if resolved_url == str(original_analysis.normalized_url):
            return original_analysis

        effective_analysis = await self.url_analysis_service.analyze_url(resolved_url)
        effective_analysis.input_url = original_analysis.input_url
        return effective_analysis

    async def analyze_scan(
        self,
        url: str,
        scan_metadata: dict[str, object] | None = None,
    ) -> ScanAnalyzeResponse:
        """Run the main scan workflow and return the rich scan response."""

        scan_id = str(uuid4())
        self.logger.info("scan_started url=%s", url, extra={"scan_id": scan_id})

        original_analysis = await self.url_analysis_service.analyze_url(url)
        original_normalized_url = str(original_analysis.normalized_url)

        redirects_result = await self._run_redirects(scan_id, original_normalized_url)
        analysis = await self._build_effective_analysis(
            original_analysis=original_analysis,
            redirects_result=redirects_result,
        )
        self._apply_redirect_result(analysis, redirects_result)
        normalized_url = str(analysis.normalized_url)
        registrable_domain = analysis.registrable_domain
        hostname = analysis.normalized_hostname

        safe_browsing_result, whois_result, reputation_result, threat_intel_result, ssl_info_result = await asyncio.gather(
            self._run_safe_browsing(scan_id, normalized_url),
            self._run_whois(scan_id, registrable_domain),
            self._run_reputation(scan_id, normalized_url),
            self._run_threat_intel(scan_id, normalized_url),
            self._run_ssl_info(scan_id, hostname),
        )

        risk = calculate_risk_score(
            ScoringInputs(
                url_analysis=analysis,
                safe_browsing=safe_browsing_result,
                whois=whois_result,
                reputation=reputation_result,
                threat_intel=threat_intel_result,
                ssl_info=ssl_info_result,
                redirects=redirects_result,
            )
        )

        gemini_result = await self._run_gemini(
            scan_id=scan_id,
            url=normalized_url,
            verdict=risk.verdict,
            score=risk.score,
            score_breakdown=risk.score_breakdown,
        )
        explanation = gemini_result.summary or risk.summary

        persistence_payload = {
            "scanned_url": url,
            "normalized_url": normalized_url,
            "registrable_domain": registrable_domain,
            "risk_score": risk.score,
            "risk_level": "danger" if risk.verdict == "dangerous" else risk.verdict,
            "flagged_safe_browsing": risk.flagged_safe_browsing,
            "flagged_threat_intel": risk.flagged_threat_intel,
            "typosquatting_detected": risk.typosquatting_detected,
            "domain_age_days": risk.domain_age_days,
            "redirect_hops": risk.redirect_hops,
            "ssl_valid": risk.ssl_valid,
            "ai_summary": explanation,
            # TODO: Align persisted JSON columns with the final Supabase schema.
            "analysis_payload": {
                "scan_id": scan_id,
                "analysis": analysis.model_dump(mode="json"),
                "risk": risk.model_dump(mode="json"),
                "safe_browsing": safe_browsing_result.model_dump(mode="json"),
                "whois": whois_result.model_dump(mode="json"),
                "reputation": reputation_result.model_dump(mode="json"),
                "threat_intel": threat_intel_result.model_dump(mode="json"),
                "ssl_info": ssl_info_result.model_dump(mode="json"),
                "redirects": redirects_result.model_dump(mode="json"),
                "gemini": gemini_result.model_dump(mode="json"),
            },
        }
        if scan_metadata:
            persistence_payload.update(
                {
                    key: value
                    for key, value in scan_metadata.items()
                    if value is not None
                }
            )
        persistence_result = await self._persist_scan(
            scan_id=scan_id,
            payload=persistence_payload,
        )

        self.logger.info(
            "scan_completed verdict=%s score=%s persisted=%s",
            risk.verdict,
            risk.score,
            persistence_result.persisted,
            extra={"scan_id": scan_id},
        )

        return ScanAnalyzeResponse(
            scan_id=scan_id,
            analysis=analysis,
            risk=risk,
            explanation=explanation,
            persisted=persistence_result.persisted,
            message=f"Analyzed {analysis.registrable_domain} successfully.",
        )
