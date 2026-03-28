"""Top-level API router."""

from fastapi import APIRouter

from app.api import dashboard, health, qr, redirect, scan

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router)
api_router.include_router(scan.router)
api_router.include_router(qr.router)
api_router.include_router(redirect.router)
api_router.include_router(dashboard.router)
