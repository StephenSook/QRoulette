from fastapi import APIRouter, Request

from db.scan_logger import log_scan
from models.contracts import ScanDecisionResponse, ScanRequest
from services.analyzer import analyze_url, normalize_url

# API-first endpoint: returns decision payload without redirecting.
router = APIRouter(prefix="", tags=["scan"])


@router.post("/scan", response_model=ScanDecisionResponse)
async def scan_url(request: Request, payload: ScanRequest) -> ScanDecisionResponse:
    # Same normalization + analysis pipeline used by /go to keep behavior aligned.
    normalized_url = normalize_url(payload.url)
    analysis = analyze_url(normalized_url)

    # Persist signals for analytics even when caller only wants JSON response.
    scan_row = {
        "scanned_url": normalized_url,
        "qr_code_id": payload.qr_code_id,
        "risk_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "flagged_safe_browsing": analysis.flagged_safe_browsing,
        "flagged_threat_intel": analysis.flagged_threat_intel,
        "typosquatting_detected": analysis.typosquatting_detected,
        "domain_age_days": analysis.domain_age_days,
        "redirect_hops": analysis.redirect_hops,
        "ssl_valid": analysis.ssl_valid,
        "ai_summary": analysis.ai_summary,
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "country": request.headers.get("cf-ipcountry"),
    }
    log_scan(scan_row)

    allowed = analysis.risk_level != "danger"
    reason = "Allowed by risk policy." if allowed else "Blocked by risk policy."
    return ScanDecisionResponse(
        allowed=allowed,
        destination=normalized_url,
        reason=reason,
        analysis=analysis,
    )
