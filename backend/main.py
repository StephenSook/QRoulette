"""ASGI entrypoint for the QRoulette backend."""
from fastapi import FastAPI

from routes.dashboard import router as dashboard_router
from routes.redirect import router as redirect_router
from routes.scan import router as scan_router

# App-level contract version used by teammates during integration.
app = FastAPI(title="QRoulette API", version="1.0.0")

# Route groups are split by responsibility:
# - /scan for API-first analysis
# - /go for real redirect flow from QR scans
# - /dashboard for analytics views
app.include_router(redirect_router)
app.include_router(dashboard_router)
app.include_router(scan_router)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/contract")
def contract_info() -> dict[str, object]:
    # Lightweight discovery endpoint so teammates can confirm active routes quickly.
    return {
        "version": "1.0.0",
        "routes": {
            "POST /scan": "Returns allow/block decision payload for frontend flows.",
            "GET /go": "Logs scan and redirects on safe URLs, blocks on danger.",
            "GET /dashboard/summary": "Returns safe/suspicious/danger counters.",
            "GET /dashboard/recent": "Returns latest scan records.",
        },
    }
