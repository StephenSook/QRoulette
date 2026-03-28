"""Shared API dependencies."""

from fastapi import Request

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.base import ServiceContext
from app.services.gemini import GeminiService
from app.services.qr_generator import QRGeneratorService
from app.services.redirects import RedirectsService
from app.services.reputation import ReputationService
from app.services.safe_browsing import SafeBrowsingService
from app.services.scan_analysis import ScanAnalysisService
from app.services.ssl_info import SSLInfoService
from app.services.supabase_repo import SupabaseRepository
from app.services.threat_intel import ThreatIntelService
from app.services.url_analysis import URLAnalysisService
from app.services.whois import WhoisService


def get_service_context(request: Request) -> ServiceContext:
    """Build the shared service context from app state."""

    return ServiceContext(
        client=request.app.state.http_client,
        settings=get_settings(),
    )


def get_url_analysis_service(request: Request) -> URLAnalysisService:
    """Return the local URL analysis service."""

    return URLAnalysisService(get_service_context(request))


def get_qr_generator_service(request: Request) -> QRGeneratorService:
    """Return the QR generator service."""

    return QRGeneratorService(get_service_context(request))


def get_redirects_service(request: Request) -> RedirectsService:
    """Return the redirects service."""

    return RedirectsService(get_service_context(request))


def get_safe_browsing_service(request: Request) -> SafeBrowsingService:
    """Return the Safe Browsing integration service."""

    return SafeBrowsingService(get_service_context(request))


def get_whois_service(request: Request) -> WhoisService:
    """Return the WHOIS integration service."""

    return WhoisService(get_service_context(request))


def get_reputation_service(request: Request) -> ReputationService:
    """Return the reputation integration service."""

    return ReputationService(get_service_context(request))


def get_threat_intel_service(request: Request) -> ThreatIntelService:
    """Return the threat-intel integration service."""

    return ThreatIntelService(get_service_context(request))


def get_ssl_info_service(request: Request) -> SSLInfoService:
    """Return the SSL inspection service."""

    return SSLInfoService(get_service_context(request))


def get_gemini_service(request: Request) -> GeminiService:
    """Return the Gemini integration service."""

    return GeminiService(get_service_context(request))


def get_supabase_repository(request: Request) -> SupabaseRepository:
    """Return the Supabase repository stub."""

    return SupabaseRepository(get_service_context(request))


def get_scan_analysis_service(request: Request) -> ScanAnalysisService:
    """Return the full scan analysis orchestrator."""

    context = get_service_context(request)
    return ScanAnalysisService(
        context,
        url_analysis_service=URLAnalysisService(context),
        safe_browsing_service=SafeBrowsingService(context),
        whois_service=WhoisService(context),
        reputation_service=ReputationService(context),
        threat_intel_service=ThreatIntelService(context),
        ssl_info_service=SSLInfoService(context),
        redirects_service=RedirectsService(context),
        gemini_service=GeminiService(context),
        supabase_repository=SupabaseRepository(context),
        logger=get_logger("qroulette.scan_analysis"),
    )
