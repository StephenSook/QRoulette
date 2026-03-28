"""Shared API dependencies."""

from fastapi import Request

from app.core.config import get_settings
from app.services.base import ServiceContext
from app.services.gemini import GeminiService
from app.services.qr_generator import QRGeneratorService
from app.services.redirects import RedirectsService
from app.services.supabase_repo import SupabaseRepository
from app.services.url_analysis import URLAnalysisService


def get_service_context(request: Request) -> ServiceContext:
    """Build the shared service context from app state."""

    return ServiceContext(
        client=request.app.state.http_client,
        settings=get_settings(),
    )


def get_url_analysis_service(request: Request) -> URLAnalysisService:
    """Return the URL analysis orchestrator."""

    return URLAnalysisService(get_service_context(request))


def get_qr_generator_service(request: Request) -> QRGeneratorService:
    """Return the QR generator service."""

    return QRGeneratorService(get_service_context(request))


def get_redirects_service(request: Request) -> RedirectsService:
    """Return the redirects service."""

    return RedirectsService(get_service_context(request))


def get_gemini_service(request: Request) -> GeminiService:
    """Return the Gemini integration service."""

    return GeminiService(get_service_context(request))


def get_supabase_repository(request: Request) -> SupabaseRepository:
    """Return the Supabase repository stub."""

    return SupabaseRepository(get_service_context(request))
