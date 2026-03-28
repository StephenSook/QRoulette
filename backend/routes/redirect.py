from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from db.scan_logger import log_scan
from models.contracts import ScanDecisionResponse, ScanRequest
from services.analyzer import analyze_url, normalize_url

# Browser-facing route used by protected QR links in the live demo flow.
router = APIRouter(prefix="", tags=["redirect"])


@router.get("/go")
async def protected_redirect(request: Request, url: str, qr_code_id: str | None = None) -> Any:
    query = ScanRequest(url=url, qr_code_id=qr_code_id)
    normalized_url = normalize_url(query.url)
    analysis = analyze_url(normalized_url)

    # Always log before allowing/blocking so dashboard captures every scan attempt.
    scan_row = {
        "scanned_url": normalized_url,
        "qr_code_id": query.qr_code_id,
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

    decision = ScanDecisionResponse(
        allowed=analysis.risk_level != "danger",
        reason=(
            "Blocked by risk policy."
            if analysis.risk_level == "danger"
            else "Allowed by risk policy."
        ),
        analysis=analysis,
        destination=normalized_url,
    )

    if analysis.risk_level == "danger":
        # Return structured block payload that UI can render directly.
        return JSONResponse(
            status_code=403,
            content=decision.model_dump(mode="json"),
        )

    # Safe URLs continue through normal browsing flow.
    return RedirectResponse(url=normalized_url, status_code=307)
