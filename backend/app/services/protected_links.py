"""Business QR protected-link workflows."""

from __future__ import annotations

import secrets

from app.core.logging import get_logger
from app.core.scoring import to_legacy_risk_analysis
from app.core.url_normalizer import normalize_url
from app.schemas.protected_links import (
    ProtectedRedirectOutcome,
    QRCreateResponse,
)
from app.schemas.repository import CreateProtectedLinkInput
from app.services.base import ServiceStub
from models.contracts import ScanDecisionResponse


class ProtectedLinkNotFoundError(LookupError):
    """Raised when a protected-link token cannot be resolved."""


class InvalidProtectedLinkUrlError(ValueError):
    """Raised when the submitted destination URL cannot be normalized safely."""


class ProtectedLinksService(ServiceStub):
    """Create and resolve tokenized protected links."""

    def __init__(
        self,
        context,
        *,
        repository,
        qr_generator_service,
        scan_analysis_service,
    ) -> None:
        super().__init__(context)
        self.repository = repository
        self.qr_generator_service = qr_generator_service
        self.scan_analysis_service = scan_analysis_service
        self.logger = get_logger("qroulette.protected_links")

    def _generate_token(self) -> str:
        """Generate a compact URL-safe token for public QR links."""

        return secrets.token_urlsafe(18)

    @staticmethod
    def _build_protected_url(base_url: str, token: str) -> str:
        """Build the public `/go/{token}` URL."""

        return f"{base_url.rstrip('/')}/go/{token}"

    async def create_protected_link(
        self,
        *,
        original_url: str,
        label: str,
        organization_id: str | None,
        base_url: str,
    ) -> QRCreateResponse:
        """Normalize, persist, and prepare a protected-link payload."""

        normalized = normalize_url(original_url)
        if not normalized.hostname_ascii:
            raise InvalidProtectedLinkUrlError("Invalid URL.")
        record = await self.repository.create_protected_link(
            CreateProtectedLinkInput(
                token=self._generate_token(),
                original_url=original_url.strip(),
                normalized_url=normalized.normalized_url,
                label=label.strip(),
                organization_id=organization_id,
                is_active=True,
            )
        )
        protected_url = self._build_protected_url(base_url, record.token)
        artifact = await self.qr_generator_service.generate(protected_url)
        return QRCreateResponse(
            token=record.token,
            protected_url=protected_url,
            qr_payload_value=artifact.payload_value,
            normalized_url=record.normalized_url,
            label=record.label,
            organization_id=record.organization_id,
            artifact=artifact,
        )

    async def resolve_redirect(
        self,
        *,
        token: str,
        client_ip: str | None = None,
        user_agent: str | None = None,
        country: str | None = None,
    ) -> ProtectedRedirectOutcome:
        """Resolve a protected link and build the reusable redirect decision."""

        record = await self.repository.get_protected_link_by_token(token)
        if record is None or not record.is_active:
            raise ProtectedLinkNotFoundError(token)

        scan_result = await self.scan_analysis_service.analyze_scan(
            str(record.normalized_url),
            scan_metadata={
                "qr_code_id": record.id,
                "organization_id": record.organization_id,
                "protected_link_id": record.id,
                "protected_link_token": record.token,
                "protected_link_label": record.label,
                "ip_address": client_ip,
                "user_agent": user_agent,
                "country": country,
            },
        )
        risk = to_legacy_risk_analysis(scan_result.risk)
        destination = (
            str(scan_result.analysis.redirect_result.final_url)
            if scan_result.analysis.redirect_result is not None
            else str(record.normalized_url)
        )
        decision = ScanDecisionResponse(
            allowed=risk.risk_level != "danger",
            destination=destination,
            reason=(
                "Blocked by risk policy."
                if risk.risk_level == "danger"
                else "Allowed by risk policy."
            ),
            analysis=risk,
        )
        return ProtectedRedirectOutcome(
            protected_link=record,
            decision=decision,
            redirect_url=destination if decision.allowed else None,
        )
